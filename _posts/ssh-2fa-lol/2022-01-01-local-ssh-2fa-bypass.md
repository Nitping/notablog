---
layout: post
title:  "Now: SSH Session Riding vs Then: SSH Session Injection. (local 2FA bypass)"
date:   2021-06-06 20:28:22 -0400
categories: web2
---

# SSH Session injection ?

Mostly personal notes after revisiting the topic recently while looking into old el8 hacking techniques of the mid 00's.

These notes serve as a reminder on the importance of reading documentation & understanding a high level overview of a target before reading/writing code to test theories.

If you read any old hack logs from the golden era of hacking then you might have seen mentions of SSH session injection. The technique would allow some one to ptrace an open ssh client and open a 2nd session to an already opened server unbeknownst to the legitimate user the remote host the were connected to was just compromised silently without modifying the sshd binary (on disk or in memory).
 
Previous public work:
Trust Transience: Post Intrustion SSH Hijacking - Metlstorm 2008 [HERE](https://www.blackhat.com/presentations/bh-usa-05/bh-us-05-boileau.pdf).

Officially "patched" in OpenSSH 5.1p1 - [HERE](https://github.com/openssh/openssh-portable/commit/8901fa9c88d52ac1f099e7a3ce5bd75089e7e731#diff-6e5958092d48b108bef3faadd24f2259a7e999ba8771cb64c986179c059fe130)


Lets examine the openssh-portable code base to see if this is still possible. If not, why?

--- ssh.c ---
```c
static int
ssh_session2(struct ssh *ssh, const struct ssh_conn_info *cinfo)
{
...
        if (options.session_type != SESSION_TYPE_NONE)
                id = ssh_session2_open(ssh); // [0] LCFR - ssh_session2_open is executed here to establish a channel/session with the server
        else {
                ssh_packet_set_interactive(ssh,
                    options.control_master == SSHCTL_MASTER_NO,
                    options.ip_qos_interactive, options.ip_qos_bulk);
        }

        /* If we don't expect to open a new session, then disallow it */
        if (options.control_master == SSHCTL_MASTER_NO &&
            (ssh->compat & SSH_NEW_OPENSSH)) {
		// [1] LCFR - the CLIENT sends no-more-sessions@openssh.com packet to the server after the call to ssh_session2_open() has finished
                debug("Requesting no-more-sessions@openssh.com");
                if ((r = sshpkt_start(ssh, SSH2_MSG_GLOBAL_REQUEST)) != 0 ||
                    (r = sshpkt_put_cstring(ssh,
                    "no-more-sessions@openssh.com")) != 0 ||
                    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
                    (r = sshpkt_send(ssh)) != 0)
                        fatal_fr(r, "send packet");
        }
...
```
--- serverloop.c ---
```c
// [2] LCFR - global variable to disable further channels/sessions

static int no_more_sessions = 0; /* Disallow further sessions. */

static int
server_input_global_request(int type, u_int32_t seq, struct ssh *ssh)
{
...
        } else if (strcmp(rtype, "no-more-sessions@openssh.com") == 0) {
		// [3] LCFR - when the CLIENT sends the "no-more-sessions@openssh.com" packet/cmd to the server the no_more_sessions variable is set to 1.
                no_more_sessions = 1;
                success = 1;
        }
...

...
static int
server_input_channel_open(int type, u_int32_t seq, struct ssh *ssh)
{
        Channel *c = NULL;
        char *ctype = NULL;
        const char *errmsg = NULL;
        int r, reason = SSH2_OPEN_CONNECT_FAILED;
        u_int rchan = 0, rmaxpack = 0, rwindow = 0;

        if ((r = sshpkt_get_cstring(ssh, &ctype, NULL)) != 0 ||
            (r = sshpkt_get_u32(ssh, &rchan)) != 0 ||
            (r = sshpkt_get_u32(ssh, &rwindow)) != 0 ||
            (r = sshpkt_get_u32(ssh, &rmaxpack)) != 0)
                sshpkt_fatal(ssh, r, "%s: parse packet", __func__);
        debug_f("ctype %s rchan %u win %u max %u",
            ctype, rchan, rwindow, rmaxpack);

        if (strcmp(ctype, "session") == 0) {
		// LCFR "session" is requested from ssh_session2_open()
		// LCFR the following function will check no_more_sessions and fail/return
                c = server_request_session(ssh);
        } else if (strcmp(ctype, "direct-tcpip") == 0) {
                c = server_request_direct_tcpip(ssh, &reason, &errmsg);
        } else if (strcmp(ctype, "direct-streamlocal@openssh.com") == 0) {
                c = server_request_direct_streamlocal(ssh);
        } else if (strcmp(ctype, "tun@openssh.com") == 0) {
                c = server_request_tun(ssh);
        }
...


static Channel *
server_request_session(struct ssh *ssh)
{
...
        Channel *c;
        int r;

        debug("input_session_request");
        if ((r = sshpkt_get_end(ssh)) != 0)
                sshpkt_fatal(ssh, r, "%s: parse packet", __func__);

	// [3] LCFR  - checks no_more_sessions is 1 and disconnects / returns 
        if (no_more_sessions) {
                ssh_packet_disconnect(ssh, "Possible attack: attempt to open a "
                    "session after additional sessions disabled");
        }

        /*
         * A server session has no fd to read or write until a
         * CHANNEL_REQUEST for a shell is made, so we set the type to
         * SSH_CHANNEL_LARVAL.  Additionally, a callback for handling all
         * CHANNEL_REQUEST messages is registered.
         */
        c = channel_new(ssh, "session", SSH_CHANNEL_LARVAL,
            -1, -1, -1, /*window size*/0, CHAN_SES_PACKET_DEFAULT,
            0, "server-session", 1);
        if (session_open(the_authctxt, c->self) != 1) {
                debug("session open failed, free channel %d", c->self);
                channel_free(ssh, c);
                return NULL;
        }
        channel_register_cleanup(ssh, c->self, session_close_by_channel, 0);
        return c;
}
...
```

# Why we cant inject a new session:

At [0] ssh_session2_open is executed here to establish a channel/session with the server.

At [1] The CLIENT sends no-more-sessions@openssh.com packet to the server after the call to ssh_session2_open() has finished

At [2] A global var "no_more_sessions" in serverloop.c to disable further channels/sessions is initialized to 0
 
At [3] in the function server_input_global_request in serverloop.c no_more_sessions is set to 1 if the CLIENT sends the string "no-more-sessions@openssh.com" this sets the no_more_sessions = 1;

At [4] in the function server_request_session in serverloop.c if a client tries to open a new session it checks if no_more_sessions = 1 and returns/disconnects the client with a warning "Possible attack: attempt to open a session after additional sessions disabled" this prevents further sessions.


# Some useless tests

Note: *reading the SSH documentation would have saved me a lot of time here.*

Here I modified the ssh client blocked no-more-sessions and called the function manually in gdb to test opening a 2nd session to test.

```bash
(gdb) x/x ssh_session2_open_lcfr
0x555555565fd0 <ssh_session2_open_lcfr>:	0xfa1e0ff3
(gdb) bt
#0  0x00007ffff7bbd002 in __GI___libc_read (fd=fd@entry=5, 
    buf=buf@entry=0x7fffffffb72f, nbytes=nbytes@entry=1)
    at ../sysdeps/unix/sysv/linux/read.c:26
#1  0x00005555555da525 in read (__nbytes=1, __buf=0x7fffffffb72f, __fd=5)
    at /usr/include/x86_64-linux-gnu/bits/unistd.h:44
#2  readpassphrase (
    prompt=prompt@entry=0x5555556426d0 "(x@localhost) Password: ", 
    buf=buf@entry=0x7fffffffbe40 "\326\320\315\341\326\320\315", <incomplete sequence \341>, bufsiz=bufsiz@entry=1024, flags=flags@entry=2)
    at readpassphrase.c:132
#3  0x00005555555ac201 in read_passphrase (
    prompt=0x5555556426d0 "(x@localhost) Password: ", flags=0)
    at readpass.c:187
#4  0x0000555555579e12 in input_userauth_info_req (type=<optimized out>, 
    seq=<optimized out>, ssh=0x5555556365c0) at sshconnect2.c:1961
#5  0x00005555555b0e6a in ssh_dispatch_run (ssh=ssh@entry=0x5555556365c0, 
    mode=mode@entry=0, done=done@entry=0x7fffffffc3f8) at dispatch.c:113
#6  0x00005555555b0f3d in ssh_dispatch_run_fatal (
    ssh=ssh@entry=0x5555556365c0, mode=mode@entry=0, 
    done=done@entry=0x7fffffffc3f8) at dispatch.c:133
#7  0x000055555557dacb in ssh_userauth2 (ssh=ssh@entry=0x5555556365c0, 
    local_user=local_user@entry=0x555555638f80 "x", 
    server_user=server_user@entry=0x55555563a0d0 "x", 
    host=host@entry=0x555555638f60 "localhost", 
    sensitive=sensitive@entry=0x55555562cba0 <sensitive_data>)
    at sshconnect2.c:482
#8  0x0000555555578eab in ssh_login (ssh=0x5555556365c0, 
    sensitive=0x55555562cba0 <sensitive_data>, orighost=<optimized out>, 
--Type <RET> for more, q to quit, c to continue without paging--q
Quit
(gdb) call ssh_session2_open_lcfr(0x5555556365c0)
$1 = 0
```

# RTFM.

It turns out reading all documentation before starting on a target withca goal may shed light on on ways to accomplish said goal. 

```
 - windows? https://github.com/PowerShell/openssh-portable/blob/latestw_all/ssh.c#L2189


2.2. connection: disallow additional sessions extension
     "no-more-sessions@openssh.com"

Most SSH connections will only ever request a single session, but a
attacker may abuse a running ssh client to surreptitiously open
additional sessions under their control. OpenSSH provides a global
request "no-more-sessions@openssh.com" to mitigate this attack.

When an OpenSSH client expects that it will never open another session
(i.e. it has been started with connection multiplexing disabled), it
will send the following global request:

        byte            SSH_MSG_GLOBAL_REQUEST
        string          "no-more-sessions@openssh.com"
        char            want-reply

On receipt of such a message, an OpenSSH server will refuse to open
future channels of type "session" and instead immediately abort the
connection.

Note that this is not a general defence against compromised clients
(that is impossible), but it thwarts a simple attack.

NB. due to certain broken SSH implementations aborting upon receipt
of this message, the no-more-sessions request is only sent to OpenSSH
servers (identified by banner). Other SSH implementations may be
listed to receive this message upon request.



6.1.  Opening a Session

   A session is started by sending the following message.

      byte      SSH_MSG_CHANNEL_OPEN
      string    "session"
      uint32    sender channel
      uint32    initial window size
      uint32    maximum packet size

   Client implementations SHOULD reject any session channel open
   requests to make it more difficult for a corrupt server to attack the
   client.
```

# How to win? RTFM - Continued: SSH Multiplexing.

It turns out that OpenSSH has supported multiplexing since version 3.9 released in 2004. SSH provides three command line options which can be used as SSH config file options as well.


```
ControlMaster
Enables the sharing of multiple sessions over a single network connection. When set to yes, ssh(1) will listen for connections on a control socket specified using the ControlPath argument. Additional sessions can connect to this socket using the same ControlPath with ControlMaster set to no (the default). These sessions will try to reuse the master instance's network connection rather than initiating new ones, but will fall back to connecting normally if the control socket does not exist, or is not listening.
Setting this to ask will cause ssh(1) to listen for control connections, but require confirmation using ssh-askpass(1). If the ControlPath cannot be opened, ssh(1) will continue without connecting to a master instance.

X11 and ssh-agent(1) forwarding is supported over these multiplexed connections, however the display and agent forwarded will be the one belonging to the master connection i.e. it is not possible to forward multiple displays or agents.

Two additional options allow for opportunistic multiplexing: try to use a master connection but fall back to creating a new one if one does not already exist. These options are: auto and autoask. The latter requires confirmation like the ask option.

ControlPath
Specify the path to the control socket used for connection sharing as described in the ControlMaster section above or the string none to disable connection sharing. Arguments to ControlPath may use the tilde syntax to refer to a user's home directory, the tokens described in the TOKENS section and environment variables as described in the ENVIRONMENT VARIABLES section. It is recommended that any ControlPath used for opportunistic connection sharing include at least %h, %p, and %r (or alternatively %C) and be placed in a directory that is not writable by other users. This ensures that shared connections are uniquely identified.

ControlPersist
When used in conjunction with ControlMaster, specifies that the master connection should remain open in the background (waiting for future client connections) after the initial client connection has been closed. If set to no (the default), then the master connection will not be placed into the background, and will close as soon as the initial client connection is closed. If set to yes or 0, then the master connection will remain in the background indefinitely (until killed or closed via a mechanism such as the "ssh -O exit"). If set to a time in seconds, or a time in any of the formats documented in sshd_config(5), then the backgrounded master connection will automatically terminate after it has remained idle (with no client connections) for the specified time.
```

The line: *Enables the sharing of multiple sessions over a single network connection.* 

Sounds a lot like SSH Session Injection if the user is unaware of it happening? At least a viable altrnative now to pivot to the 2FA protected SSH jump box you may be targetting ;) 

## OFFENSIVE USE Example:

An unsuspecting user/admin opens a master connection to a remote host. 

For subsequent connections, route slave connections through the existing master connection by setting the ControlMaster and ControlPath options
in the targets ~/.ssh/config

```
ControlMaster auto
ControlPath ~/.ssh/control:%h:%p:%r
```

If an attacker starts an ssh session to the same (user, port, machine) as an existing connection, the second session will be tunneled over the first using the same open connection.

This can be used with a hidden .ssh/config to bypass needing SSH keys, 2FA codes etc for attackers 

# EOF

Metlstorm suggested that RDP may be vulnerable to similar in the past in his talk. 🤷‍♂️
Audit tip: check SSH implementations when auditing to see if they disallow further sessions after initial session creation.
