import pickle
import pprint
import sys

from ircsrp import *

cmd = sys.argv[1]
filename = sys.argv[2]

if cmd == "read":
    roster = pickle.load(open(filename, 'r'))
    pprint.pprint(roster.db)
elif cmd == "write":
    user = sys.argv[3]
    password = sys.argv[4]
    s, v = ircsrp_generate(user, password)
    roster = open(filename, "w")
    i = IRCSRPUsers();
    i.db = { user : (s, v) }
    roster.write(pickle.dumps(i))
    print "Wrote roster for user", user, "to", filename
