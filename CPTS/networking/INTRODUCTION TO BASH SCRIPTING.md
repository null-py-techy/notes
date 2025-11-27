## Shebang

The shebang line is always at the top of each script and always starts with "`#!`". This line contains the path to the specified interpreter (`/bin/bash`) with which the script is executed. We can also use Shebang to define other interpreters like Python, Perl, and others.

Code: python

## Special Variables

Special variables use the [Internal Field Separator](https://bash.cyberciti.biz/guide/$IFS) (`IFS`) to identify when an argument ends and the next begins. Bash provides various special variables that assist while scripting. Some of these variables are:

|**Special Variable**|**Description**|
|---|---|
|`$#`|This variable holds the number of arguments passed to the script.|
|`$@`|This variable can be used to retrieve the list of command-line arguments.|
|`$n`|Each command-line argument can be selectively retrieved using its position. For example, the first argument is found at `$1`.|
|`$$`|The process ID of the currently executing process.|
|`$?`|The exit status of the script. This variable is useful to determine a command's success. The value 0 represents successful execution, while 1 is a result of a failure.|

Of the ones shown above, we have 3 such special variables in our `if-else` condition.

| **Special Variable** | **Description**                                                                                                                                                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `$#`                 | In this case, we need just one variable that needs to be assigned to the `domain` variable. This variable is used to specify the target we want to work with. If we provide just an FQDN as the argument, the `$#` variable will have a value of `1`. |
| `$0`                 | This special variable is assigned the name of the executed script, which is then shown in the "`Usage:`" example.                                                                                                                                     |
| `$1`                 | Separated by a space, the first argument is assigned to that special variable.                                                                                                                                                                        |
## String Operators

If we compare strings, then we know what we would like to have in the corresponding value.

| **Operator** | **Description**                             |
| ------------ | ------------------------------------------- |
| `==`         | is equal to                                 |
| `!=`         | is not equal to                             |
| `<`          | is less than in ASCII alphabetical order    |
| `>`          | is greater than in ASCII alphabetical order |
| `-z`         | if the string is empty (null)               |
| `-n`         | if the string is not null                   |
## Integer Operators

Comparing integer numbers can be very useful for us if we know what values we want to compare. Accordingly, we define the next steps and commands how the script should handle the corresponding value.

| **Operator** | **Description**             |
| ------------ | --------------------------- |
| `-eq`        | is equal to                 |
| `-ne`        | is not equal to             |
| `-lt`        | is less than                |
| `-le`        | is less than or equal to    |
| `-gt`        | is greater than             |
| `-ge`        | is greater than or equal to |
## File Operators

The file operators are useful if we want to find out specific permissions or if they exist.

| **Operator** | **Description**                                        |
| ------------ | ------------------------------------------------------ |
| `-e`         | if the file exist                                      |
| `-f`         | tests if it is a file                                  |
| `-d`         | tests if it is a directory                             |
| `-L`         | tests if it is if a symbolic link                      |
| `-N`         | checks if the file was modified after it was last read |
| `-O`         | if the current user owns the file                      |
| `-G`         | if the file’s group id matches the current user’s      |
| `-s`         | tests if the file has a size greater than 0            |
| `-r`         | tests if the file has read permission                  |
| `-w`         | tests if the file has write permission                 |
| `-x`         | tests if the file has execute permission               |
## Logical Operators

With logical operators, we can define several conditions within one. This means that all the conditions we define must match before the corresponding code can be executed.

| **Operator** | **Description**        |
| ------------ | ---------------------- |
| `!`          | logical negotation NOT |
| `&&`         | logical AND            |
| `\|`         | logical OR             |
#### Arithmetic Operators

|**Operator**|**Description**|
|---|---|
|`+`|Addition|
|`-`|Subtraction|
|`*`|Multiplication|
|`/`|Division|
|`%`|Modulus|
|`variable++`|Increase the value of the variable by 1|
|`variable--`|Decrease the value of the variable by 1|#### If-Elif-Else.sh

We can also calculate the length of the variable. Using this function `${#variable}`, every character gets counted, and we get the total number of characters in the variable.



```bash
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi
```

![[Pasted image 20250901211525.png]]

Question 1:Create an "If-Else" condition in the "For"-Loop of the "Exercise Script" that prints you the number of characters of the 35th generated value of the variable "var". Submit the number as the answer.
```
#!/bin/bash

var="nef892na9s1p9asn2aJs71nIsm"

for counter in {1..40}
do
    var=$(echo $var | base64)
    
    if [ $counter -eq 35 ]; then
        echo $(echo -n $var|wc -c )
    fi
done
```
	->1197735
#### Arrays.sh

Code: bash

```bash
#!/bin/bash

domains=("www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com" www2.inlanefreight.com)
echo ${domains[0]}
```
Question 2 :Submit the echo statement that would print "www2.inlanefreight.com" when running the last "Arrays.sh" script.
	->echo ${domains[1]}

![[Pasted image 20250902125356.png]]

Question 3:Create an "If-Else" condition in the "For"-Loop that checks if the variable named "var" contains the contents of the variable named "value". Additionally, the variable "var" must contain more than 113,450 characters. If these conditions are met, the script must then print the last 20 characters of the variable "var". Submit these last 20 characters as the answer.
```
#!/bin/bash

var="8dm7KsjU28B7v621Jls"
value="ERmFRMVZ0U2paTlJYTkxDZz09Cg"

for i in {1..40}
do
    var=$(echo "$var" | base64)

    # If-Else condition
    if [[ "$var" == *"$value"* && ${#var} -gt 113450 ]]; then
        echo "${var: -20}"   # print last 20 characters
    else
        :   # do nothing (placeholder)
    fi
done

```
	->2paTlJYTkxDZz09Cg==

Question 4:Create a "For" loop that encodes the variable "var" 28 times in "base64". The number of characters in the 28th hash is the value that must be assigned to the "salt" variable.

```#!/bin/bash

# Decrypt function
function decrypt {
    MzSaas7k=$(echo $hash | sed 's/988sn1/83unasa/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/4d298d/9999/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/3i8dqos82/873h4d/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/4n9Ls/20X/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/912oijs01/i7gg/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/k32jx0aa/n391s/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/nI72n/YzF1/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/82ns71n/2d49/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/JGcms1a/zIm12/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/MS9/4SIs/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/Ymxj00Ims/Uso18/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/sSi8Lm/Mit/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/9su2n/43n92ka/g')
    Mzns7293sk=$(echo $MzSaas7k | sed 's/ggf3iunds/dn3i8/g')
    MzSaas7k=$(echo $Mzns7293sk | sed 's/uBz/TT0K/g')

    flag=$(echo $MzSaas7k | base64 -d | openssl enc -aes-128-cbc -a -d -salt -pass pass:$salt)
}

# Variables
var="9M"
salt=""
hash="VTJGc2RHVmtYMTl2ZnYyNTdUeERVRnBtQWVGNmFWWVUySG1wTXNmRi9rQT0K"

# Base64 Encoding Example:
#        $ echo "Some Text" | base64

# <- For-Loop here
for i in {1..28}

do

var=$(echo "$var" | base64)

done

salt=$(echo "$var" | wc -c)

# Check if $salt is empty
if [[ ! -z "$salt" ]]
then
    decrypt
    echo $flag
else
    exit 1
fi
```
	->HTBL00p5r0x