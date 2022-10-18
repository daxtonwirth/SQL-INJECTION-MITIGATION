

def genQuery(username, password):
    # accepts two input parameters and returns a SQL string.
    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL

def genQuryWeak(username, password):
    # provide a weak mitigation against all four attacks
    
    # Tautology mitigation
    password.replace("'", "")

    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL

def genQueryStrong(username, password):
    # provide a strong mitigation against all command injection attacks
    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL


def testValid():
    # demonstrate the query generation function works as expected with a collection of test cases
    # that represent valid input where the username and the password consist of letters, numbers, and underscores
    testcaseusernames = ["bob", "Sue", "greg"]
    testcasepasswords = ["Password1", "123456", "QUERTY_1"]
    for user in testcaseusernames:
        for password in testcasepasswords:
            print(genQuery(user, password))


def testTautology():
    # Demonstrates a tautology attack. 
    # Feeds the test cases through the query function and displays the output.
    username = "Bob"
    password = "Passowrd' OR '1' = '1"
    print(genQuery(username,password))

def testUnion():
    pass

def testAddState():
    pass

def testComment():
    pass
     
print("TESTING VALID CASES")
testValid()
print("\nTESTING TAUTOLOGY")
testTautology()
