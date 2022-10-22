

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

    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL

def genQueryStrong(username, password):
    # provide a strong mitigation against all command injection attacks
    count = 0
    safeChars = [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,1,2,3,4,5,6,7,8,9,0,_]
    for char in username:
        if char not in safeChars:
            newUsername = username.slice[:count] + username.slice[count+1:]
            username = newUsername
            count -= 1
        count += 1

    SQL = f"SELECT authenticate FROM passwordList WHERE name='{username}' and passwd='{password}'"
    return SQL


def testValid():
    # demonstrate the query generation function works as expected with a collection of test cases
    # that represent valid input where the username and the password consist of letters, numbers, and underscores
    testcaseusernames = ["bob", "Sue", "greg", "myUsername_123"]
    testcasepasswords = ["Password1", "123456", "QUERTY_1", "great_Password456"]
    for user in testcaseusernames:
        for password in testcasepasswords:
            print(genQuery(user, password))


def testTautology():
    # Demonstrates a tautology attack.
    # Feeds the test cases through the query function and displays the output.
    username = "Bob"
    password = "Passowrd' OR '1' = '1"
    print(genQuery(username,password))

    userB = "dad_"
    passB = "fake123' OR 'mom' = 'mom"
    print(genQuery(userB,passB))

    userC = "Billy"
    passC = "'nothing' OR 'abc' = 'abc'"
    print(genQuery(userC, passC))

def testUnion():
    #Demonstrates a union attack
    username = "George"
    password = "'password' UNION SELECT authenticate FROM passwordList"
    print(genQuery(username, password))

def testAddState():
    #Demonstrates an additional statement attack
    username = "Sam"
    password = "'nothing'; INSERT INTO passwordList (name, passwd) VALUES 'Eve', '1111';"
    print(genQuery(username, password))

def testComment():
    #Demonstrates a comment attack
    username = "'Root'; --"
    password = "nothing"
    print(genQuery(username, password))

print("TESTING VALID CASES")
testValid()
print("\nTESTING TAUTOLOGY")
testTautology()
print("\nTESTING UNION")
testUnion()
print("\nTESTING ADDITIONAL STATEMENT")
testAddState()
print("\nTESTING COMMENT")
testComment()
