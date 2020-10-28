# Parentage

Hubblestack started life as a Salt execution module meant to be
run in a Salt environment. It later evolved into a stand alone
daemon by borrowing heavily from the Salt daemon code.

The next stage in this evolution is to remove the salt-ssh
dependency from Hubblestack. This dependency is/was essentially
all of Salt.

The removal of the Salt dependency is not meant to hide or
occlude this relationship. The point is to remove the parts of
Salt that Hubblestack nolonger needs (the minion/master
relationship, any sort of message bus, various types of template
systems, and a few other things) and to avoid having to worry
about surprise upstream changes that break Hubblestack.

# Licensing

The Apache license requires, among other things, that we do not
remove any copyright or license information from any files copied
into Hubblestack from Salt. It may be the case that some parts of
Hubblestack are direct or even indirect copies of concepts from
Salt that may not have carried a specific license at the time.

Hubblestack has the same LICENSE file as Salt. Should there every
be any doubt about the origin of a section of code in the future,
please assume that it did come from Salt; and should therefore
carry whatever LICENSE restrictions it did in Salt.
