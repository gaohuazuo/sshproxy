# sshproxy

An enhanced `ssh -D` socks5 proxy. It uses a connection pool for better bandwidth utilization an latency.

## Usage

Make sure you can ssh to server using `~/.ssh/id_rsa` then build and run

`./sshproxy [-l address:port] [-p poolsize] [username@]server[:port]`

A larger pool size will have better peak performance, but also longer time-to-peak. `-p 8` would be a good initial try for pool size.

Setting congestion control to BBR on server side may help with download bandwith. Likewise setting congestion control to BBR on local machine may improve upload bandwidth.

Currently client side keepalive is not implemented so it is recommended to configure `ClientAliveInterval` and `ClientAliveCountMax` in server `sshd_config`.