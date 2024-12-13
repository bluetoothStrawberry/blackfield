![](images/banner.png)

| Target       |
| ------------ |
| 10.10.10.192 |

### 100.1 Fingerprinting

```sh
ping -c1 10.10.10.192
```
![](images/ping.png)

> TTL 127 Windows System 1 Hop Away

```
nxc smb 10.10.10.192
```
![](images/smb.png)

| IP Address   | NetBIOS | Domain           | OS                                  |
| ------------ | ------- | ---------------- | ----------------------------------- |
| 10.10.10.192 | DC01    | blackfield.local | Windows Server 2019 Build 17763 x64 |

---

200.1 