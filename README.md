## Snort(Suricata) Rule File Creation and Traffic Detection for Specific Websites

In this exercise, we created a Snort(Suricata) rule file to detect traffic for specific websites. The process was as follows:

#### 1. Rule Creation:
We wrote rules in the `test.rules` file to detect traffic for 20 different websites.

#### 2. Function Verification:
After creating the rules, we checked the `fast.log` file to verify that the rules were functioning correctly. Specifically, we ensured that traffic for all domains was logged in the `fast.log` file, confirming that the traffic for each site was properly detected.

#### 3. TLS Detection Implementation:
In addition to detecting traffic for websites using plaintext communication (HTTP), we also implemented traffic detection for websites using TLS communication (HTTPS). This helped establish a more accurate detection environment.

![화면 캡처 2025-04-23 172052v2](https://github.com/user-attachments/assets/51dd3cc6-a33c-4274-b78d-1d60c1c5b1ad)




<br><br>
## ❗Caution: Limitation of Using Only content in Rules
![image](https://github.com/user-attachments/assets/fb1c2da6-f99f-42c9-9177-62ffcf006881)
<br><br>
If you define a rule like this:
```suricata
alert tcp any any -> any 80 (msg:"gilgil.net access"; content:"GET /"; content:"Host: "; content:"gilgil.net"; sid:10001; rev:1;)
```
Suricata will trigger an alert if all the specified strings appear in the payload in order, regardless of their context.
This means even a malformed or unrelated HTTP request like the following could trigger an alert:
``` suricata
GET / HTTP/1.1
Host: www.naver.com

gilgil.net
```
In this example, although the actual Host is www.naver.com, the presence of the string gilgil.net somewhere else in the payload is enough to match the rule.
This leads to false positives.




<br><br>
## ✅ Better Approach: Use HTTP Keywords
To accurately detect access based on the actual HTTP host header, it's better to use Suricata’s HTTP parser keywords like http.method and http.host:
``` suricata
alert http any any -> any 80 (msg:"HTTP GET request to gilgil.net"; http.method; content:"GET"; http.host; content:"gilgil.net"; sid:10002; rev:1;)
```
This rule ensures that an alert is only triggered when:
- The HTTP method is GET
- The Host header exactly contains gilgil.net
This approach reduces false positives and provides more precise detection.
