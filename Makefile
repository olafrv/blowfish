###  
#   This file is part of Blowfish.
#
#   Copyright (C) Aug, 2024 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
#
#   Blowfish is free software: you can redistribute it and/or modify
#
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Blowfish is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Blowfish.  If not, see <http://www.gnu.org/licenses/>.
##

default: run

run: classes
	java -classpath ./src/main/java BlowfishExample
	java -classpath ./src/main/java Blowfish2Example

classes: clean 
	javac -classpath ./src/main/java ./src/main/java/*.java

clean:
	find ./src/main/java -name '*.class' -exec rm -f {} \; 
	
test: clean
	gradle wrapper
	gradle clean test
	gradle test
	# gradlew tasks
