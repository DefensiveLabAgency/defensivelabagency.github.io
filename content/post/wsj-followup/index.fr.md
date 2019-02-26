---
title: "Retour sur nos analyses d'applications mobiles utilisant Facebook réalisées pour le Wall Street Journal"
date: 2019-02-26
tags: [iOS, Android, Facebook, RGPD]
draft: false
---

Le 22-02-2019, le Wall Street Journal publiait [un article d'investigation détaillé](https://www.wsj.com/articles/you-give-apps-sensitive-personal-information-then-they-tell-facebook-11550851636). On y apprend que de nombreuses applications mobiles, dans leurs versions iOS, traitant des données de santé communiquent lesdites données à Facebook, que vous y soyez connecté·e ou pas. Defensive Lab Agency a été sollicitée pour conduire ces mêmes analyses sur Android. Au vu de la faible maturité sur le sujet, nous avons décidé d'expliciter une partie de notre expertise sur le sujet et d'illustrer les conclusions du Wall Street Journal avec quelques éléments techniques.

Par le passé, nous avons déjà montré que lorsque l'on ouvre une application, elle peut envoyer des données à Facebook sans que nous soyons au courant. On a également beaucoup parlé de "shadow profiles", soit des profils Facebook qui ne sont pas créés par les personnes elles-mêmes. Si vous avez déjà assisté à nos conférences, vous avez certainement vu nos exemples d'analyses sur la façon dont ces "shadow profiles" sont construits. Ainsi, dire que Facebook collecte des données à l'insu des utilisateurs·trices d'applications tierces n'est pas vraiment une nouveauté.

<h2>Les conclusions d'abord</h2>

Les aspects explicités par l'article du Wall Street Journal illustrent de façon frappante la main-mise de Facebook sur de nombreuses applications : il s'agit ici d'applications auxquelles on confie des données de santé, données envoyées à Facebook sans qu'on y soit connecté·e ou sans même qu'on y ait un profil. Dans cette étude, 11 applications populaires, comptant des dizaines de millions de téléchargements, ont été passées au crible à la fois technique et légal. Nous avons regardé leurs comportements (quelles données elles collectent, à qui elles les envoient) et la correspondance entre ces comportements et les politiques de confidentialité.

Voici donc ce que nous avons constaté :

* Parmi les 11 applications, il y a Instant Heart Rate: HR Monitor qui collecte votre rythme cardiaque&#8239;; Flo Period & Ovulation Tracker utilisée pour le suivi menstruel et les cycles ovulatoires (qui aide notamment les utilisatrices à savoir quand elles sont fertiles...)&#8239;; des applications de suivi d'activité sportive pour la perte de poids&#8239;; l'application de Realtor.com permettant de suivre les prix de l'immobilier (et donc, de savoir quel bien je veux acheter et quel est ma santé financière), etc.
* Ces applications collectent et transmettent à Facebook les données (de santé, financières) des utilisateurs·trices sans qu'iels en soient préalablement informé·es&#8239;;
* Facebook collecte ces données sans se préoccuper de savoir si vous, qui utilisez l'appli, êtes identifié·e sur Facebook ou même si vous y avez un compte&#8239;;
* Il est impossible pour la personne utilisant l'application d'empêcher que ses données soient envoyés chez Facebook.

<h2>Comment ces données s'en vont-elles chez Facebook ?</h2>

L'envoi de données collectées par une application et envoyées à Facebook se fait grâce à une brique technique créée par Facebook : un SDK. Facebook permet aux entreprises développant des applications de les monétiser en diffusant de la publicité via lesdites applis. Pour ce faire, l'entreprise inclut le SDK nommé Facebook Ads. Ce SDK dépend de Facebook Core&#8239;; ce dernier est construit pour collecter des AppEvents (des évènements que crée une application : afficher l'écran d'accueil, cliquer sur un bouton, changer d'écran, etc.). De nombreux AppEvents sont captés de façon automatique, comme le précise [la documentation y afférente de Facebook](https://developers.facebook.com/docs/app-events/getting-started-app-events-android#7--add-app-events). La documentation relative à [Facebook Core](https://developers.facebook.com/docs/android/componentsdks) dit clairement que la collecte de métriques se fait quel que soit le SDK utilisé&#8239;; cette collecte est automatique. Vous pouvez également vous référer à la documentation de Facebook sur les [AppEvents spécifiques à la publicité](https://www.facebook.com/business/help/235457266642587). 

{{< fig src="img/automatic_app_event.png" caption="Extrait de la documentation de Facebook indiquant la collecte automatique d'AppEvent." >}}

Si nous lisons la documentation pour développeurs d'applications fournie par Facebook, les AppEvents collectés automatiquement contiennent (sans se limiter à) IDFA/AID, les métadonnées du smartphone, le nom (ou handle) de l'application, un identifiant non-modifiable par l'utilisateur·trice, etc. Ces termes signifient :

* IDFA/AID sont respectivement les noms donnés aux identifiants publicitaires uniques associés au smartphone sur lequel est installée et utilisée l'application : IDFA (IDentifier For Advertisers dans le cas d'iOS) et AID (Advertising ID dans le cas d'Android). Par conséquent, Facebook sait lorsque l'applicagttion de votre entreprise est installée ou lancée (et également, lorsque le SDK, la brique servant à la monétisation donc, est activée). Nous pouvons faire l'analogie entre un identifiant publicitaire mobile et un cookie publicitaire posé par un site web : les deux servent à "mémoriser" nos préférences et à dresser un profil plus précis de nos comportements de consommation et d'intérêts. Cependant, cette analogie est plutôt imprécise : un cookie web a une durée de vie plutôt réduite, contrairement à un identifiant publicitaire mobile lequel ne change que si l'utilisateur·trice décide de le modifier.
* Le handle d'une application sert aux annonceurs de marqueur démographique. 
* L'identifiant non-modifiable par l'utilisateur·trice, également connu en tant qu'anon_id, est généré au premier lancement de l'application et persiste jusqu'à la désinstallation. Dans le cas des applications Android, par exemple, il est toujours envoyé conjointement à l'AID.

<h2>Un identifiant publicitaire mobile est une donnée à caractère personnel</h2>

Comment ces éléments interagissent-ils entre eux ? Prenons deux applications Android qui utilisent chacune le SDK de Facebook : chaque application génère un anon_id différent. Cependant, l'AID est associé au smartphone et non pas à l'application. Ainsi, lorsque l'AID est transmis (dans le flot des différentes métadonnées collectées), Facebook peut établir la correspondance entre les 2 anon_id, appartenant à 2 applications distinctes, et l'AID du smartphone sur lequel elles sont installées. Facebook sait donc que ces 2 applications sont utilisées par le même appareil&#8239;; en collectant des données à caractère personnel supplémentaires, il sait également qui utilise l'appareil et donc à qui ces informations se rapportent. 

Comme dit plus haut, l'AID est permanent jusqu'à sa suppression (réinitialisation ou opt-out). Si l'on souhaite le regénérer, par exemple pour associer un AID différent suite à une désinstallation-réinstallation d'une application, cela ne fait qu'enrichir les informations que Facebook a sur nous : un nouvel anon_id sera associé à l'application fraîchement réinstallée. Même si le couple AID-anon_id est nouveau, il existe d'autres données transmises à Facebook (métadonnées du smartphone, etc. : cf. supra) qui permettront d'assurer la correspondance de profils.

Si l'on réfléchit à ces notions sous le prisme du RGPD, nous constatons qu'un identifiant publicitaire mobile est une donnée à caractère personnel. Pour les plus oublieux, rappel de l'Art. 4 du Règlement : une information permettant d'identifier, directement ou indirectement, un individu est une donnée à caractère personnel.

Revenons donc à cette entreprise éditant une application mobile et souhaitant la monétiser grâce à de la publicité proposée notamment via Facebook. L'application contient le SDK de Facebook lequel consomme de nombreuses données y compris à caractère personnel, comme nous venons de le décrire. Pour permettre à l'entreprise de segmenter son audience et donc de cibler plus finement la publicité, les dévéloppeurs peuvent envoyer des Custom AppEvents : des [évènements spécifiques à une application et personnalisés](https://developers.facebook.com/docs/app-events/getting-started-app-events-android#custom-events). Ces évènements personnalisés contiennent les données d'un AppEvent normal complémentées des données supplémentaires.

<h2>Le cas de l'application BetterMe</h2>

BetterMe est l'une des applications étudiées pour l'article du Wall Street Journal. Elle nous servira à illustrer ce qui a été expliqué plus haut tout en démontrant le comportement de l'application ayant servi aux conclusions de l'article Wall Street Journal.

BetterMe est l'entreprise éditrice de plusieurs applications liées à différents aspects de ce que l'entreprise considère comme une vie saine : l'alimentation, l'activité sportive, les relations amoureuses/sexuelles, les remèdes naturels et la beauté. Ainsi, BetterMe fait autant des applications destinés aux femmes (une application éponyme mais aussi BetterMenstrual, pour le suivi des règles) qu'aux hommes (BetterMen)&#8239;; on peut y trouver "24 conseils d'étiquette pour dames", "10 astuces psychologiques pour qu'il tombe amoureux de vous" et autres "raisons pourquoi les femmes doivent faire davantage d'exercices que les hommes". Nous ne nous prononçons pas sur la qualité de ces contenus, cela serait hors sujet.

BetterMe envoie à Facebook le poids, la taille, le poids souhaité, les objectifs d'exercices avec les niveaux de difficulté, le nom et le temps passé à faire chacune de ces activités physiques ainsi que le nombre d'exercices finis. Via l'outil d'analyse de Facebook, reposant sur les métriques collectées, BetterMe peut cibler par exemple les personnes utilisant son application et ayant un IMC > 18 (indiquant un surpoids) avec des publicités pour des régimes, des liposuccions, des anneaux gastriques, des cliniques spécialisées, etc.

Passons donc aux éléments techniques nous permettant de dire que les données à caractère personnel (dont de santé) sont collectées par BetterMe et transmises à Facebook. Ces éléments concernent l'application en sa version 2.12.9&#8239;; le hash SHA256 de l'APK est `a2cae25fc5250dbd20e9a67c7048aa1b7ddac8fe5695f089013866ed8cf43f79` :

{{< fig src="img/normal_app_event.png" caption="AppEvent collecté automatiquement, notifiant Facebook de l'installation de l'application." >}}

{{< fig src="img/custom_app_event_taille.png" caption="Custom AppEvent envoyant à Facebook la taille que l'utilisateur·trice de BetterMe a renseignée." >}}

De même, chaque changement d'écran dans l'application (correspondant à une action) est envoyé à Facebook : nous y voyons ainsi envoyé le passage de l'écran on précise son poids vers l'écran où on spécifie son poids souhaité :

{{< fig src="img/custom_app_event_poids.png" caption="Custom AppEvent envoyant à Facebook le poids que l'utilisateur·trice de BetterMe a renseigné." >}}

Il est notable de remarquer que, bien que nos captures ci-dessus soient issues de l'analyse de l'application Android, ce comportement de l'application vis-à-vis de Facebook est identique dans sa version iOS.

Le Wall Street Journal a publié une suite de l'article du 22-02-2019 : le dimanche 24-02-2019, [le journal faisait état](https://www.wsj.com/articles/popular-apps-cease-sharing-data-with-facebook-11551044791) d'au moins 4 applications (parmi les 11 identifiées comme indûment communiquant des données à Facebook) ayant fait des mises à jour. D'après nos analyses, BetterMe a fait une mise à jour de son application le 19-02-2019, soit 3 jours avant la sortie de l'article d'investigation du Wall Street Journal. Cette modification est probablement en réaction aux questions du journaliste. Quelle que soit la raison de la mise à jour, le comportement de l'applicaqtion ne semble pas avoir changé. 

Ainsi, d'après nos analyses de la version 2.12.13 (le hash SHA256 de l'APK est `9ce0560d980b930a9826c9939e15d81e7eb88bdabe644c784598b14fce3d3a3e`), les Custom AppEvents sont de cette forme :

{{< fig src="img/betterme_new_version.png" caption="Custom AppEvent envoyant à Facebook les poids et taille saisis par l'utilisateur·trice de BetterMe." >}}

<h2>Conclusion préliminaire</h2>

Ces observations ne sont qu'un aspect. Mais alors, quid du RGPD et de la responsabilité des magasins applicatifs ? Après tout, si nous lisons la [Politique de confidentialité de BetterMe](https://betterme.tips/privacy.html) par exemple, nous constatons que la société éditrice des applications de la famille BetterMe est de droit privé chypriote. Chypre étant un État-membre de l'UE, le RGPD s'applique. Or, la Politique de confidentialité que nous avons analysée, ne semble pas refléter les exigences du RGPD.

Mais nous en parlerons au prochain épisode ! D'ici là, n'oubliez pas de [vous abonner à notre lettre d'information](https://defensive-lab.agency/fr/#suivre-notre-actualit%C3%A9) (si ce n'est pas déjà fait).  