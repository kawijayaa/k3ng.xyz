---
icon: fingerprint
---

# Grayscale

### Challenge Description

A threat actor hides a secret message on this intentionally-broken GIF.

Author: farisv

### Flag

`CJ{_s0_15_it_pr0nounc3d_GiF_or_JiF?_}`

***

### Analysis

We are given a file that according to the description is a broken GIF file. When opened with a hex editor, the header part of the GIF is filled with `FF` bytes.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 074757.png" alt=""><figcaption><p>Hex editor view of the file</p></figcaption></figure>

### Solution

To recover this file, we need to modify the first 16 bytes of the file based on the [GIF specification](https://en.wikipedia.org/wiki/GIF#Example_GIF_file). The reason why we only need to modify the first 16 bytes and not all of the header is that since we can infer from the challenge name that this image will be grayscale, we only need to change the Logical Screen Descriptor and the first two colors of the Global Color Table so that other colors are interpreted as `FF` or white.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 075439 (1).png" alt=""><figcaption><p>Hex editor view after modification</p></figcaption></figure>

When opening the file with an image viewer after modification, we will see the flag displayed.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 075502.png" alt=""><figcaption><p>Image of the flag</p></figcaption></figure>
