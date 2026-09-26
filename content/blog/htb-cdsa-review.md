---

title: How to Pass the Hack The Box Certified Defensive Security Analyst Exam (as a CTF Player)
date: 2026-09-23
thumbnail: /images/htb_cdsa_review/thumbnail.jpg
description: On the 22nd of September 2026, I received an email from Hack The Box saying that I had successfully passed the Certified Defensive Security Analyst exam. This post will outline my experience and I will share some tips on how to pass this exam from the perspective of an avid forensics CTF player.
---

# Background

For some context, I had been playing CTFs for four years, mainly in the forensics category. That gave me much of my experience in digital forensics and incident response. Through CTFs, I gained experience using forensics tool such as Wireshark, FTK Imager, Volatility, and SIEMs such as Splunk. As a result, most of the concepts covered by the certification were already familiar to me.

# Course

To be eligible for the exam, you are required to complete the SOC Analyst Job-Role path. I paid for the course using the student discount for A$13 per month. I started working on the course in May 2025 and finished the course six months later in November. I did the course in a very relaxed manner without any sort of target, so I think the course could realistically be completed in less than three months.

![](/images/htb_cdsa_review/cdsa_2.png)

The course consists of 15 modules covering a wide range of defensive security concepts such as incident handling, SIEMs, Windows investigation, malware analysis, and incident reporting. I don't have too much to say about the course so I'll keep this section short.

I think the course is great, especially the practical assessments in some modules. I personally liked the SIEM modules and the Windows Attacks & Defense module. Those modules are essential if you are looking to work in a defensive security team. The most important module in the whole course is Security Incident Reporting, where you learn how to create a professional report of an incident. While very short, the explanations and examples given are essential for the exam.

But there are some shortcomings with the course itself. For one, connectivity to the lab VMs is slow at best. This is insanely frustrating when the VMs are essential for completing the module, such as analysing an incident through a SIEM. The difficulty varies too much between modules for my liking, with some modules taking only minutes to complete while another might take hours or even days for beginners. One particularly difficult module is Introduction to Malware Analysis. I think that module is way too hard relative to the other modules and could be removed or modified to make the difficulty more consistent.

# Hesitation

Once I completed the course, I was very hesitant to take the exam because I was not comfortable with writing a report required for the exam. Because of that, I put the exam aside for some time and did not attempt it until 10 months later.

The turning point came when I joined SOCsim, a course built by Dalan Coburn. This course is designed to provide exposure to incident response and SOC analysis through Microsoft Defender. One of the course requirements was to create a [report](https://k3ng.xyz/blog/project-victoria/) for an incident. Dalan was kind enough to give me thorough feedback on how I constructed the report and critiqued my methodology. The advice I received gave me enough confidence to finally take the exam.

# Exam

The exam itself requires you to analyse two independent incidents within seven days, with one of the incidents requiring you to get 16 out of 20 flags. You are then required to write and submit a professional report covering both incidents. Since I did not have the annual subscription, I had to purchase the exam voucher separately for around A$325.

## Preparation
None.

Yes, you read that correctly. I did not prepare anything leading up to the exam. I impulsively bought the voucher and started the exam right away. Was that a responsible choice? Not really.

## Start

The first two days went smoothly, and I got 19 out of 20 flags on the first incident. I also sloppily took screenshots of my analysis without any real organisation. I thought I had made a good amount of progress on the first incident. Looking back, that couldn't have been further from the truth.

## Realisation

Around three days after I started my attempt, I realised that I needed to start my report soon. After installing Obsidian in the middle of the exam, I started to reconstruct my findings from the flags I had gathered from the previous days. This basically meant redoing everything I had done over the last few days because I did not document everything. 

While gathering all of the evidence that I had found over the past few days, I realised that the exam was not as easy as I thought it would be after finding massive gaps in my analysis. As I scrambled to gather findings to cover the gaps, I started to understand the attack path of the first incident and ended up with decent documentation for each step. And I still had the audacity to keep my report empty at this stage, which was a huge mistake.

The next day, I realised something I should've recognised much earlier: I had not analysed the second incident. I gathered up all my remaining energy, moved on to the second incident and botched together a somewhat coherent analysis. At this stage, I still had not drafted anything for my final report.

## Final Push

With both incidents reasonably well documented, I started drafting a report for each incident in Obsidian. When I was somewhat satisfied with the results, I began moving my report into SysReptor. Hack The Box was kind enough to provide a template for the report so that you don't need to worry about formatting. SysReptor was also amazing to use because you can just fill in the fields and SysReptor handles the final document formatting.

One day before the exam deadline, I decided that my report was coherent enough, submitted the report to the platform, and let out a huge sigh of relief.

After holding my breath for two weeks, I finally received the email that I had successfully passed the exam!

![](/images/htb_cdsa_review/cdsa_1.png)

# Tips

## 1. Obsidian

Obsidian is basically required for this exam. It will help you so much with documenting findings and combining each finding into a coherent analysis. I used Obsidian's Canvas feature to create a graph connecting my notes so I could see the attack path visually. Since each node on the canvas can link to a note, I could keep the evidence inside each note while still visualising the overall attack path.

![](/images/htb_cdsa_review/cdsa_3.png)

## 2. Break Down Tasks

If the goal in your mind is too broad (e.g., "Analyse this incident"), you may get overwhelmed and procrastinate. Break the task down into smaller parts so that each task can be completed in a short amount of time.

## 3. Don't Fixate on Flags

In this exam, you are acting as a security analyst rather than a CTF player. You are tasked with understanding the incidents rather than collecting flags to get points. The flags can provide hints about what might be happening, but they're not a crutch for understanding the incident.

## 4. Cheatsheets

Prepare a cheatsheet for things that you may need to refer to, such as Windows event IDs or common SIEM queries. This will save you a lot of time that would otherwise be spent Googling or asking AI.

## 5. Document as You Go

While analysing, keep track of everything you find immediately in Obsidian. When you find an interesting log, document your SIEM query, the log results, timestamps, and other relevant indicators in a note in Obsidian. Don't worry too much if your notes are incoherent for the time being. You can fix that later. The most important thing is to make sure you don't waste time re-analysing things you have already found just because you forgot to take a screenshot or save the SIEM query.

# Conclusion

The overall package of the course and exam is excellent. It teaches you a lot about defensive security at a relatively affordable price compared to other certifications (looking at you OffSec). The exam itself is incredibly realistic with awesome attack paths, evidence, and a professional report template.

I usually divide cyber security certifications into two categories: HR-oriented certifications and educational certifications. I think the CDSA fits more into the educational category since most companies are unaware of this certifications, but I have seen some more niche cyber security companies starting to recognise it. If you are looking to get a certification purely to get through HR filters, this is not the one for you. But if you are looking for a certification that will help you learn about defensive security, this is a great choice for you.

# Retrospective

From this experience, I obviously learned heaps about the technical craft of defensive security, such as writing cool SIEM queries. But I did not expect to learn so much about the parts of defensive security that aren't mentioned very often. I learned a lot about time management, evidence organisation, managing log fatigue, and report writing. And I feel like those were some of the most valuable lessons from the experience, and I will be carrying forward into my professional career.
