This is a tool to fast sign jar with certificate on an USB token. 
Oracle jarsigner tool have the problem of access USB to calculate jar classes hashes an this critically slow down the overall process when jar contains thousands of elements.

Usage:

With installed driver and connected token, using a java version >= 1.8, type:

> java -jar GST-jarsigner-1.0.jar  [parameters] jar-file alias

mandatory parameters

-providerArg <file>                  token configuration file

-storepass <password>                token password

optional parameters:

[-test]                              debug output

[-signaturename <file>]              name of file .SF/.RSA

[-tsa <url>]                         Timestamping Authority URL

example:

>java -jar GST-jarsigner-1.0.jar  -test -signaturename MYSIGNNAME -providerArg C:\eToken.cfg -storepass *** -tsa http://rfc3161timestamp.globalsign.com/advanced application.jar "te-ed12c5f8-6b3e-43c4-8461-7f58b7325a46"

Example of configuration file eToken.cfg:

name=eToken
library=c:\WINDOWS\system32\eTPKCS11.dll

The tool will sign jar-file with certificate on token specified with alias. Sign Algorihtm is SHA256_RSA.

I realized this project starting from this:

https://github.com/kaikramer/keystore-explorer

taking a look to Oracle jarsigner code for the token interaction, and removing the graphical stuff to use it in an automatic maven build.

This is a little example of use in maven:

```xml
...
<plugin>
	<groupId>org.codehaus.mojo</groupId>
	<artifactId>exec-maven-plugin</artifactId>
	<executions>
		<execution>
		<id>Sign ${project.artifactId}-${project.version} with certificate on token</id>
			<goals>
				<goal>exec</goal>
			</goals>
			<phase>package</phase>
			<configuration>
				<executable>${java8.home}/bin/java</executable>
				<arguments>
					<argument>-jar</argument>
					<argument>${signJar-jar}</argument>
					<argument>-providerArg</argument>
					<argument>${confirmatoken-configurationfile}</argument>
					<argument>-tsa</argument>
					<argument>${tsaUrl}</argument>
					<argument>-storepass</argument>
					<argument>${token-password}</argument>
					<argument>target/${project.artifactId}-${project.version}.jar</argument>
					<argument>${confirmatoken-alias}</argument>
				</arguments>
			</configuration>
		</execution>
	</executions>
</plugin>
 ...
```

I'm not a java expert and I went right to the result for my needs.
 
So you will find a lot of "dirty" code :), but I can assure it works fine for the purpouse!

