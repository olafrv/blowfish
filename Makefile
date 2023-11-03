###  
#   This file is part of Blowfish.
#
#   Copyright (C) Dec 23th, 2009 - Olaf Reitmaier Veracierta <olafrv@gmail.com>
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

CLASSES = \
	BlowfishException.java \
	Blowfish.java \
	BlowfishTest.java

default: clean-only-classes classes

classes: 
	javac -classpath ../ $(CLASSES)

run:
	java -classpath ../:. BlowfishTest

clean:
	rm -f *.class *.java~
	ls -l
	
clean-only-classes:
	rm -f *.class

