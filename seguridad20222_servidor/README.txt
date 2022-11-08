compile server:
  javac src/seguridad20222_servidor/*.java

run server:
  java -classpath src seguridad20222_servidor.ServidorMain

----

compile client
  javac src/security_client/*.java

run client (while server is running):
  java -classpath src security_client.ClientMain
