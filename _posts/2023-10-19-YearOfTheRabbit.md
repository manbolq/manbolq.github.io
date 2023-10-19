---
title: Year of the Rabbit
date: 2023-10-09 18:47:00 +0200
categories: [Writeups, TryHackMe]
tags: [fuzzing, hydra, ftp, brainfuck, ssh, sudo]
img_path: /assets/images/YearOfTheRabbit
---


To solve this TryHackMe machine, we will have to look at some CSS code, as inside a file there will be some useful comments. Using BurpSuite and intercepting some requests, we will discover a new directory serving a photo. There are some credentials stored in the image and we will use hydra to guess the correct one. We will run some Brainfuck code and exploit an outdated version of sudo and a sudoers privilege in order to get root shell.

## Recognisement

First of all. We are going to check if the machine is active. To do so, we can try to ping the machine: `ping -c1 10.10.110.84`

![ping result](ping.png)

The machine replies to us, sending back the ICMP packet. Based on TTL, we can think that the machine is running Linux. 

Let's use **nmap** to discover the open ports the machine has over TCP. We can execute the following command:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.110.84 -oG allPorts
```
which is going to be fast as well as effective. This is the output:

![nmap open ports](nmap-open-ports.png)

So ports **21** (FTP), **22** (SSH) and **80** (HTTP) open. Let's run a more exhaustive scan to these specific ports. To do that we are going to execute:

```bash
nmap -p21,22,80 -sCV 10.10.110.84 -oN targeted
```

And this is the output

![nmap full scan](nmap-full-scan.png)

A pretty much updated version of **vsftpd** and a pretty much **outdated** version of **OpenSSH**. This should be vulnerable to user enumeration. We can have this in mind for a future need. About the web, nothing really interesting, just the Apache2 default page.

As we have nothing interesting, let's enumerate the web service. We can do some fuzzing with **gobuster**:

![gobuster](gobuster.png)

`/assets` is the only useful directory that gobuster shows us. Inside there is a RickRoll (damn) and a `styles.css`, where we see this comment:

```css
/* Nice to see someone checking the stylesheets.
   Take a look at the page: /sup3r_s3cr3t_fl4g.php
*/
```

## Shell as gwendoline

If we take a look at `/sup3r_s3cr3t_fl4g.php`, we are redirected to `/sup3r_s3cret_fl4g/`, and there it is the RickRoll video. As there is some redirection, let's see what is happening intercepting the request with **BurpSuite**. 

![hidden directory](hidden-dir.png)

We see a new directory `/WExYY2Cv-qU`. Inside that directory there is just a .png file. We download it a run **strings** to it, to see if there is any readable string inside the characters of the image.

![strings command](strings.png)

So we have a username: **ftpuser** and a bunch of possible passwords. Let's save all of them in a file called `passwords.txt` and let's run **hydra** to try to guess the password:

```bash
hydra -l ftpuser -P passwords.txt ftp://10.10.110.84
```

![hydra bruteforce](hydra-ftp.png)

And so now we can connect to FTP service

![ftp service](ftp.png)

There is a file called Eli's_Creds.txt. We download it and read it and...this is the content:

![elis creds](elis-creds.png)

This looks like Brainfuck code. Brainfuck is an esoteric programming language. Let's try to run it using an online website. 

![brainfuck execution](brainfuck.png)

And there we go. Some creds to connect to SSH!

![ssh login](ssh-login.png)

Apparently root is not happy with the user **Gwendoline**. He want him to go to their "s3cr3t" directory... Let's run 

```bash
find / -name \*s3cr3t\* 2>/dev/null
```

to see if some directory appears and... `/usr/games/s3cr3t`! Inside, there is a hidden file with the creds to connect as gwendoline.

![gwendoline login](gwendoline.png)

## Privilege escalation

We can check for sudoers privileges:

![sudo -l](sudol.png)

So we can execute **vi** as every user, without a password, except for root. However, if we check sudo version with `sudo --version`, it is  1.8.10, which is an older version than 1.8.28. There is a vulnerability (CVE-2019-14287) that allows us to execute the command as the root user, despite being specified that we cannot run the command as the root user. In order to exploit that, we can give **sudo** the user identifier -1:

```bash
sudo -u#-1 vi /home/gwendoline/user.txt
```

inside the vi console, we type `ESC + :set shell=/bin/bash` and then `:shell` ....and magic works!

![root](root.png)

I hope you liked this writeup and found it useful!

