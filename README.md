# tp1_secu

**Level00**
level00@nebula:/bin/...$ find / -user flag00 2>/dev/null trouve flag00 partout
Le programme change le UID effectif et permet d'éxecuter un programme pour lequel on devrait pas avoir la permission (getflag)

CWE250:
The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.


