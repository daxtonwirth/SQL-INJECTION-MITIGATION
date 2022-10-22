

def genQuery(username, password):
    # accepts two input parameters and returns a SQL string.
    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL

def genQueryWeak(username, password):
    # provide a weak mitigation against all four attacks

    # Comment mitigtion
    username.replace("-","")
    password.replace("-","")
    # Additional statement
    username.replace(";","")
    password.replace(";","")
    # Tautology & Union mitigation
    password.replace("'", "")
    password.replace("'","")

    return genQuery(username, password)

def genQueryStrong(username, password):
    # provide a strong mitigation against all command injection attacks
    count = 0
    safeChars = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","1","2","3","4","5","6","7","8","9","0","_"]
    for char in username:
        if char not in safeChars:
            newUsername = username.slice[:count] + username.slice[count+1:]
            username = newUsername
            count -= 1
        count += 1

    return genQuery(username, password)



def testValid(type):
    # demonstrate the query generation function works as expected with a collection of test cases
    # that represent valid input where the username and the password consist of letters, numbers, and underscores
    testcaseusernames = ["bob", "Sue", "greg", "myUsername_123"]
    testcasepasswords = ["Password1", "123456", "QUERTY_1", "great_Password456"]
    
    print("\nTESTING VALID CASES")

    iterate = 0

    for username in testcaseusernames:
        testAll(type, username, testcasepasswords[iterate])
        iterate +=1

def testTautology(type):
    # Demonstrates a tautology attack.
    # Feeds the test cases through the query function and displays the output.
    print("\nTESTING TAUTOLOGY")

    username = "Bob"
    password = "Passowrd' OR '1' = '1"
    testAll(type, username, password)


    username = "dad_"
    password = "fake123' OR 'mom' = 'mom"
    testAll(type, username, password)


    username = "Billy"
    password = "'nothing' OR 'abc' = 'abc'"
    testAll(type, username, password)


def testUnion(type):
    #Demonstrates a union attack
    print("\nTESTING UNION")

    username = "George"
    password = "'password' UNION SELECT authenticate FROM passwordList"

    testAll(type, username, password)


def testAddState(type):
    #Demonstrates an additional statement attack
    print("\nTESTING ADDITIONAL STATEMENT")

    username = "Sam"
    password = "'nothing'; INSERT INTO passwordList (name, passwd) VALUES 'Eve', '1111';"
    
    testAll(type, username, password)


def testComment(type):
    #Demonstrates a comment attack
    print("\nTESTING COMMENT")

    username = "'Root'; --"
    password = "nothing"
    
    testAll(type, username, password)


def testAll(type, username, password):
    if type == 0:
        print(genQuery(username, password))
    elif type == 1:
        print(genQueryWeak(username, password))
    else: 
        print(genQueryStrong(username, password))


    

# Test each case
for x in range(0,3):
    testValid(x)
    testTautology(x)
    testUnion(x)
    testAddState(x)
    testComment(x)
    print()

