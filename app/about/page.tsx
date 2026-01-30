export default function About() {
  const experiences = [
    {
      title: "DownUnderCTF Organizer",
      description: "Developed forensics challenges for DownUnderCTF since 2025.",
      date: "",
    },
    {
      title: "BSides Brisbane CTF Challenge Author",
      description: "Developed 2 forensics challenges for the on-site CTF competition.",
      date: "Jul 2025",
    },
    {
      title: "RECURSION 1.0 Problemsetter",
      description: "Developed 2 forensics challenges for the CTF competition.",
      date: "Jul 2025",
    },
    {
      title: "Vice Person In Charge of CTF COMPFEST 16",
      description: "Managed and organised one of the largest CTF competitions in Indonesia. Also curated and developed forensics challenges for the competition.",
      date: "2024",
    },
    {
      title: "Scientific Committee of CTF COMPFEST 15",
      description: "Developed challenges for the competition's qualification round.",
      date: "2023",
    },
  ];
  const achievements = [
    {
      title: "ACUCyS Jingle Shells CTF 2025 Winner",
      description: "Won with the team \"UQ Cyber Squad: A Christmas Miracle\"",
      date: "Dec 2025",
    },
    {
      title: "The Australian Cyber Security Games 2025 2nd Place",
      description: "Achieved 2nd place with the team \"UQ \"The Squad\" CyberSquad\"",
      date: "Jul 2025",
    },
    {
      title: "CrikeyCon X CTF 3rd Place",
      description: "Achieved 3rd place with the team name \"AWAVAUATUSH\" consisting of UQ Cyber Squad members.",
      date: "Mar 2025",
    },
    {
      title: "BackdoorCTF Winner",
      description: "Achieved 1st place on the capture-the-flag competition with \"ADA INDONESIA COY\", a merger of the top CTF players of Indonesia.",
      date: "Dec 2024",
    },
    {
      title: "PwC Indonesia Hack A Day 2024 2nd Place",
      description: "Achieved 1st Runner Up in Indonesia and fourth globally with the team name \"Sudah Adakah Yang Gantikank3ng\".",
      date: "Nov 2024",
    },
    {
      title: "Cyber Jawara 2024 International 2nd Place",
      description: "Achieved 2nd place with \"swusjask fans club\", a merger between 4 top university teams of Indonesia (Universitas Indonesia, Institut Teknologi Sepuluh Nopember, Institut Pertanian Bogor, Universitas Gunadarma).",
      date: "Oct 2024",
    },
    {
      title: "CTF TCP1P International Winner",
      description: "Won with the team name of \"dimas fans club\", a merger between CSUI (Universitas Indonesia), HCS (Institut Teknologi Sepuluh Nopember), CSI (Institut Pertanian Bogor) and CCUG (Universitas Gunadarma).",
      date: "Oct 2024",
    },
    {
      title: "GEMASTIK 2024 Keamanan Siber (Cyber Security) Finalist",
      description: "Reached Top 20, going by the name \"HengkerNgangNgong\" and participated in the Finals with the Attack-Defense format at UNNES Semarang.",
      date: "Aug 2024",
    },
    {
      title: "Technofair 11.0 CTF 3rd Place",
      description: "3rd place out of 10 teams that participated in the finals, going by the name \"635 days since last finals\".",
      date: "Jul 2024",
    },
    {
      title: "CTF COMPFEST 14 Finalist",
      description: "Top 15 out of 117 teams going by the team name \"HengkerNgangNgong\".",
      date: "Sep 2022",
    },
  ];

  function getBorderColor(title: string) {
    if (title.includes("Winner")) return "border-yellow-400";
    if (title.includes("2nd")) return "border-gray-400";
    if (title.includes("3rd")) return "border-amber-700";
    return "border-fd-accent";
  }

  return (
    <main className="container mx-auto max-w-4xl px-6 py-24">
      <h1 className="text-4xl font-extrabold mb-8 text-center">About Me</h1>
      <section className="mb-12 prose mx-auto">
        <p>
          Hello! I am k3ng, an Indonesian CTF player and cyber-security student
          currently playing for CSUI and UQ Cyber Squad. I have participated in
          CTFs since 2022 and mainly does Web Exploitation and Forensics challenges.
          I also do create challenges from time to time.
        </p>
        <p>
          This site hosts writeups from previous competitions and also blog posts about
          things that interests me in cyber-security (probably around topics such as
          forensics, threat hunting, etc.)
        </p>
      </section>
      <section className="mb-12">
        <h2 className="text-3xl font-bold mb-6">Experiences</h2>
        <ul className="space-y-6">
          {experiences.map(({ title, description, date }) => (
            <li
              key={title}
              className="border-l-4 pl-4 border-fd-accent"
            >
              <h3 className="text-xl font-semibold">{title}</h3>
              <p className="text-fd-muted-foreground mb-1">{description}</p>
              <time className="text-sm text-fd-muted-foreground">{date}</time>
            </li>
          ))}
        </ul>
      </section>
      <section>
        <h2 className="text-3xl font-bold mb-6">Achievements</h2>
        <ul className="space-y-6">
          {achievements.map(({ title, description, date }) => (
            <li
              key={title}
              className={`border-l-4 pl-4 ${getBorderColor(title)}`}
            >
              <h3 className="text-xl font-semibold">{title}</h3>
              <p className="text-fd-muted-foreground mb-1">{description}</p>
              <time className="text-sm text-fd-muted-foreground">{date}</time>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}

