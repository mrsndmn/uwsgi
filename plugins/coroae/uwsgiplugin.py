import os
import sys

NAME = 'coroae'

coroapi = None

search_paths = os.popen('perl -MConfig -e \'print $Config{sitearch}.",".join(",", @INC);\'').read().rstrip().split(',')
for p in search_paths:
    if os.path.exists(p + '/Coro/CoroAPI.h'):
        coroapi = p

if not coroapi:
    print "unable to find the Coro perl module !!!"
    sys.exit(1)

CFLAGS = [ cf for cf in os.popen('perl -MExtUtils::Embed -e ccopts').read().rstrip().split() if not cf.startswith("-fstack") and not cf.startswith("-specs") ]
CFLAGS += ['-Wno-int-to-pointer-cast', '-Wno-error=format', '-Wno-error=int-to-pointer-cast', '-I%s/Coro' % coroapi]
LDFLAGS = []
LIBS = []

GCC_LIST = ['coroae']
