"""Built-in dictionaries for the strength estimator.

COMMON_PASSWORDS is ordered by how often the password shows up in public leaks (rank = position),
as far as it could be written down from published top-password lists; it is deliberately small,
because the estimator is a first filter. Breach checking (hibp.py) is the real test.
COMMON_WORDS covers frequent English and Italian words, first names and places.
Everything is lower case; the estimator undoes capitalisation and leetspeak before looking up.
"""

from __future__ import annotations

COMMON_PASSWORDS = """\
123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball
abc123 football monkey letmein shadow master 666666 qwertyuiop 123321 mustang 1234567890
michael 654321 superman 1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan
jennifer zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger sunshine iloveyou
2000 charlie robert thomas hockey ranger daniel starwars klaster 112233 george computer michelle
jessica pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa
ginger princess joshua cheese amanda summer love ashley nicole chelsea biteme matthew access
yankees 987654321 dallas austin thunder taylor matrix william corvette hello martin heather
secret fucker merlin diamond 1234qwer gfhjkm hammer silver 222222 88888888 anthony justin
test bailey q1w2e3r4t5 patrick internet scooter orange 11111 golfer cookie richard samantha
bigdog guitar jackson whatever mickey chicken sparky snoopy maverick phoenix camaro sexy
peanut morgan welcome falcon cowboy ferrari samsung andrea smokey steelers joseph mercedes
dakota arsenal eagles melissa boomer booboo spider nascar monster tigers yellow xxxxxx 123123123
gateway marina diablo bulldog qwer1234 compaq purple hardcore banana junior hannah 123654
porsche lakers iceman money cowboys 987654 london tennis 999999 ncc1701 coffee scooby 0000
miller boston q1w2e3r4 fuckoff brandon yamaha chester mother forever johnny edward 333333
oliver redsox player nikita knight fender barney midnight please brandy chicago badboy iwantu
slayer rangers charles angel flower bigdaddy rabbit wizard bigdick jasper enter rachel chris
steven winner adidas victoria natasha 1q2w3e4r jasmine winter prince panties marine ghbdtn
fishing cocacola casper james 232323 raiders 888888 marlboro gandalf asdfasdf crystal 87654321
12344321 sexsy golden blowme bigtits 8675309 panther lauren angela bitch spanky thx1138 angels
madison winston shannon mike toyota blowjob jordan23 canada sophie password1 password123
qwerty123 admin admin123 root toor welcome1 letmein1 changeme default guest login passw0rd
p@ssw0rd p@ssword qwerty1 abc12345 iloveyou1 monkey1 dragon1 football1 master1 sunshine1
princess1 1q2w3e 1q2w3e4r5t 1qazxsw2 zaq12wsx qazwsxedc asdfghjkl asdf1234 qweasdzxc qwe123
q1w2e3 aa123456 a123456 a1b2c3 abcd1234 abcdef abcdefg abcdefgh abc1234 12qwaszx 1234abcd
123abc 123456a 123456q 123456789a 1234567a 12345678a 11223344 00000000 99999999 10203040
147258369 741852963 963852741 789456123 321654987 159357 135790 246810 asd123 asdasd zxczxc
qweqwe qwaszx qazqaz passpass pass1234 pass123 test123 test1234 testtest tester guest123
user user123 demo temp temp123 oracle sqlserver postgres mysql ubuntu linux debian windows
microsoft google apple facebook twitter instagram youtube netflix amazon paypal ciao ciao123
ciaociao amore amore123 tiamo juventus juve1897 forzajuve milan inter napoli roma lazio torino
italia italia90 roma123 password! password1! welcome123 summer2020 summer2021 summer2022
summer2023 summer2024 winter2020 winter2021 winter2022 winter2023 winter2024 spring2024 autumn2024
estate2024 inverno2024 primavera2024 luglio2024 settembre2024 gennaio2024
""".split()

COMMON_WORDS = """\
the and that have for not with you this but his from they say her she will one all would
there their what out about who get which when make can like time just him know take people
into year your good some could them see other than then now look only come its over think
also back after use two how our work first well way even new want because any these give
day most man woman child world life hand part place case week company system program question
government number night point home water room area story fact month lot right study book
eye job word business issue side kind head house service friend father power hour game line
end member law car city community name president team minute idea kid body information parent
face others level office door health person art war history party result change morning reason
research girl guy moment air teacher force education foot boy age policy music market sense
nation plan college interest death experience effect class control care field development
role effort rate heart drug show leader light voice wife police mind price report decision
son view relationship town road arm difference value building action model season society
tax director position record paper space ground form event official matter center couple
site project activity star table need court oil situation cost industry figure street image
phone data picture practice piece land product doctor wall patient worker news movie north
support technology step baby type attention film tree source organization hair window culture
chance brother energy period course plant opinion christmas january february march april
may june july august september october november december monday tuesday wednesday thursday
friday saturday sunday red blue green black white pink brown gray grey gold dog cat bird
fish horse tiger lion bear wolf eagle shark mouse snake butterfly rose sun moon sky rain
snow wind fire earth ocean river mountain forest island beach pizza pasta beer wine cake
cherry lemon chocolate sugar honey bread john david mark paul kevin brian jason ryan jacob
nicholas eric jonathan stephen larry scott benjamin samuel gregory alexander frank raymond
jack dennis jerry tyler aaron henry douglas peter adam nathan zachary walter kyle harold
carl jeremy keith roger gerald ethan arthur terry christian sean lawrence joe noah jesse
albert bryan billy bruce willie dylan alan ralph gabriel roy juan wayne eugene logan randy
louis russell vincent philip bobby bradley mary patricia linda elizabeth barbara susan sarah
karen nancy lisa betty margaret sandra kimberly emily donna dorothy carol deborah stephanie
rebecca sharon laura cynthia kathleen amy shirley helen anna brenda pamela katherine emma
ruth christine catherine debra carolyn janet virginia maria diane julie joyce kelly christina
joan evelyn judith olivia frances martha cheryl megan jacqueline ann jean alice kathryn gloria
teresa doris sara janice julia marie grace judy theresa beverly denise marilyn amber danielle
abigail brittany diana natalie sophia alexis lori kayla jane marco luca giuseppe giovanni
antonio mario francesco alessandro matteo lorenzo davide simone federico riccardo stefano
roberto paolo giulia chiara francesca valentina elena martina alessia giorgia silvia milano
firenze venezia bologna genova palermo sicilia sardegna toscana piemonte lombardia casa mare
sole luna stella cuore vita gatto cane amici famiglia lavoro scuola calcio musica estate
inverno primavera autunno rosso verde azzurro nero bianco giallo
""".split()
