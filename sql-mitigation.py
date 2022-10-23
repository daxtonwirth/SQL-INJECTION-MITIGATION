# Needed for regular expressions
import re

#######
#Function Definitions
#######


## genQuery
# Accepts two input parameters and returns a SQL string meant for user authentication
def genQuery(username, password):
    return f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
## End genQuery

## genQueryWeak
# Provides a weak mitigation against all four attacks
def genQueryWeak(username, password):

    # Comment mitigtion
    username.replace("-","")
    password.replace("-","")
    # Additional statement
    username.replace(";","")
    password.replace(";","")
    # Tautology & Union mitigation
    username.replace("\'", "")
    password.replace("\'", "")

    return genQuery(username, password)
## End genQueryWeak

## genQueryStrong
# Provides a strong mitigation against all command injection attacks
# Only allows letters, numbers, and the "_" characters
def genQueryStrong(username, password):
    regex = re.compile('\w|_')
    
    rUsername = re.findall(regex, username)
    newUsername = ''
    for x in rUsername:
        newUsername = newUsername + x

    rPassword = re.findall(regex, password)
    newPassword = ''
    for x in rPassword:
        newPassword = newPassword + x

    password = newPassword
    username = newUsername

    return genQuery(username, password)
## End genQueryStrong

## testValid
# Demonstrates that the query generation function works as expected with a collection of test cases
# that represent valid input where the username and the password consist of letters, numbers, and underscores
def testValid(type):
    testcaseusernames = ["bob", "Sue", "greg", "myUsername_123"]
    testcasepasswords = ["Password1", "123456", "QUERTY_1", "great_Password456"]
    
    print("\nTESTING VALID CASES")

    iterate = 0
    for username in testcaseusernames:
        testAll(type, username, testcasepasswords[iterate])
        iterate +=1
## End testValid

## testTautology
# Demonstrates a tautology attack by adding OR plus an always true statement into the code
# Feeds the test cases through the selected query function/mitigation (type) and displays the output
def testTautology(type):
    print("\nTESTING TAUTOLOGY")

    username = "Bob"
    password = "Password' OR '1' = '1"
    testAll(type, username, password)

    username = "bob_burt"
    password = "fake123' OR 'mom' = 'mom"
    testAll(type, username, password)

    username = "admin"
    password = "nothing' OR 1=1"
    testAll(type, username, password)

    username = "root"
    password = "root' OR 1=1"
    testAll(type, username, password)
## End testTautology

## testUnion
# Demonstrates a union attack by adding UNION SELECT plus code designed to retrieve more information from the database
# Feeds the test cases through the selected query function/mitigation (type) and displays the output
def testUnion(type):
    print("\nTESTING UNION")

    username = "George"
    password = "password' UNION SELECT authenticate FROM passwordList;"
    testAll(type, username, password)

    username = "root"
    password = "password' UNION SELECT authenticate FROM passwordList WHERE name=root;"
    testAll(type, username, password)

    username = "money"
    password = "password' UNION SELECT creditcard FROM bank;"
    testAll(type, username, password)

    username = "passwords"
    password = "password' UNION SELECT password FROM authentication;"
    testAll(type, username, password)
## End testUnion

## testAddState
# Demonstrates an additional statement attack by adding a line ender ; plus code designed to modify the database
# Feeds the test cases through the selected query function/mitigation (type) and displays the output
def testAddState(type):
    print("\nTESTING ADDITIONAL STATEMENT")

    username = "Sam"
    password = "nothing'; INSERT INTO passwordList (name, passwd) VALUES 'Eve', '1111';"
    testAll(type, username, password)

    username = "admin"
    password = "'; INSERT INTO passwordList (name, passwd) VALUES 'admin', 'admin';"
    testAll(type, username, password)

    username = "hacktivist"
    password = "'; DROP DATABASE voting;"
    testAll(type, username, password)

    username = "DOS"
    password = "'; DROP DATABASE authentication;"
    testAll(type, username, password)
## End testAddState

## testComment
# Demonstrates a comment attack by adding a line ender ; plus the comment symbol -- which effectively removes any subsequent code from executing
# Feeds the test cases through the selected query function/mitigation (type) and displays the output
def testComment(type):
    print("\nTESTING COMMENT")

    username = "root'; --"
    password = "nothing"
    testAll(type, username, password)

    username = "admin'; --"
    password = ""
    testAll(type, username, password)

    username = "administrator'; --"
    password = ""
    testAll(type, username, password)

    username = "JBiden'; --"
    password = ""
    testAll(type, username, password)
## End testComment

## testAll
# Test the specific type of mitigation where 0 is the Standard Query, 1 is the Weak Mitigation, and 2 is the Strong Mitigation
def testAll(type, username, password):
    if type == 0:
        print(genQuery(username, password))
    elif type == 1:
        print(genQueryWeak(username, password))
    else: 
        print(genQueryStrong(username, password))
## End testAll
    
#######
#Main Code Execution
#######

# Test each case
for x in range(1,3):
    # Normal without mitigation
    if x == 0:
        display = "NO"
    # Weak mitigation function applied
    elif x == 1:
        display = "WEAK"
    # Strong mitigation applied
    elif x == 2:
        display = "STRONG"

    # Display which query mitigation type is being tested
    print(f"\nTesting {display} MITIGATION")
    
    # Run through each test for the specified mitigation
    testValid(x)
    testTautology(x)
    testUnion(x)
    testAddState(x)
    testComment(x)
