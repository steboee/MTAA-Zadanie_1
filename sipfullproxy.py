import datetime
import math
import socketserver
import re
import string
import socket
# import threading
import sys
import time
import logging

rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^Decline")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
# rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
# rx_invalid = re.compile("^192\.168")
# rx_invalid2 = re.compile("^10\.")
# rx_cseq = re.compile("^CSeq:")
# rx_callid = re.compile("Call-ID: (.*)$")
# rx_rr = re.compile("^Record-Route:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionnary
recordroute = ""
topvia = ""
registrar = {}
duration_p = []
global p
p = 0

def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):

    def debugRegister(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def changeRequestUri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])
        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def checkValidity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())
        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    def getSocketInfo(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def sendResponse(self, code):
        print(code)

        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line, ";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = "l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        bytes = ("\r\n")
        text = bytes.join(data).encode("utf-8")
        self.socket.sendto(text, self.client_address)
        showtime()
        who = self.data[2]
        who2 = self.data[3]
        start2 = who2.find("\"") + 1
        end2 = who2.find("\" <")
        start1 = who.find("\"") + 1
        end1 = who.find("\" <")
        user1 = who[start1:end1]
        user2 = who2[start2:end2]
        if code != "480 Temporarily Unavailable":
            logging.info("---REGISTRATION---      User %s successfully registered\n", user1)
            logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
        else:
            logging.info("%s     User %s is currently unavailable. Please call again later\n",self.data[5], user2)

    def processRegister(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)
            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.sendResponse("200 0K")
                return
        else:
            now = int(time.time())
            validity = now + expires

        #logging.info("From: %s - Contact: %s" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debugRegister()
        self.sendResponse("200 0K")

    def processInvite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            #logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                sep = "\r\n"
                text = sep.join(data).encode("utf-8")
                socket.sendto(text, claddr)
                showtime()
                #logging.info("<<< %s" % data[0])
                print("PIPIK")
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("480 Temporarily Unavailable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processAck(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.getDestination()
        if len(destination) > 0:
            #logging.info("destination %s" % destination)
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                sep = "\r\n"
                text = sep.join(data).encode("utf-8")
                socket.sendto(text, claddr)
                showtime()
                #logging.info("<<< %s" % data[0])
                print("SD")
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processNonInvite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.getOrigin()
        if len(origin) == 0 or origin not in registrar:
            self.sendResponse("400 Bad Request")
            return
        destination = self.getDestination()
        if len(destination) > 0:
            #logging.info("destination %s" % destination)
            if destination in registrar and self.checkValidity(destination):
                socket, claddr = self.getSocketInfo(destination)
                # self.changeRequestUri()
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                sep = ("\r\n")
                text = sep.join(data).encode("utf-8")
                socket.sendto(text, claddr)
                showtime()
                #logging.info("      PROXY >>> BOB %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.sendResponse("406 Not Acceptable")
        else:
            self.sendResponse("500 Server Internal Error")

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                sep = ("\r\n")
                text = sep.join(data).encode("utf-8")
                socket.sendto(text, claddr)
                showtime()

                #logging.info("<<< %s" % data[0])

                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def processRequest(self):
        global p
        # print "processRequest"
        if len(self.data) > 0:

            request_uri = self.data[0]
            print("URI ::: ")
            print(request_uri)
            if rx_register.search(request_uri):
                print("1")
                self.processRegister()
            elif rx_invite.search(request_uri):
                print("2")
                self.processInvite()
            elif rx_ack.search(request_uri):
                who = self.data[2]
                who2 = self.data[3]
                if self.data[3][5] == "s":
                    start2 = who2.find("p:") + 2
                    end2 = who2.find("@")
                else:
                    start2 = who2.find("\"") + 1
                    end2 = who2.find("\" <")
                start1 = who.find("\"") + 1
                end1 = who.find("\" <")
                user1 = who[start1:end1]
                user2 = who2[start2:end2]


                if self.data[5][2] != "n": # Contact: blabla
                    WAS_ = False
                    for call in duration_p:
                        if call[0] == self.data[5]:
                            WAS_ = True

                    if WAS_ == False:  #ošetrenie , z windows na iphone mi dvakrát choidlo ACK na zodvihntie

                        logging.info("%s     %s answered a call with %s",self.data[5],user2,user1)
                        list = [self.data[5],time.time()]
                        duration_p.append(list)
                        p = p + 1
                        print(p)
                        print(duration_p)


                self.processAck()
            elif rx_bye.search(request_uri):
                who = self.data[2]
                who2 = self.data[3]
                if self.data[3][5] == "s":
                    start2 = who2.find("p:") + 2
                    end2 = who2.find("@")
                else:
                    start2 = who2.find("\"") + 1
                    end2 = who2.find("\" <")

                if self.data[2][7] == "s":
                    start1 = who.find("p:") +2
                    end1 = who.find("@")
                else:
                    start1 = who.find("\"")+1
                    end1 = who.find("\" <")

                user1 = who[start1:end1]
                user2 = who2[start2:end2]

                duration = time.time()
                for calls in duration_p:
                    if calls[0] == self.data[5]:
                        duration = duration - calls[1]
                        break

                duration = math.ceil(duration)
                duration = "{:.0f}".format(duration)

                logging.info("%s     %s ended Call with %s",self.data[5], user1, user2)
                logging.info("%s     Duration : %s seconds\n",self.data[5],duration)
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                print("DOPICI")
                self.processNonInvite()
            elif rx_options.search(request_uri):
                self.processNonInvite()
            elif rx_info.search(request_uri):
                self.processNonInvite()
            elif rx_message.search(request_uri):
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                self.processNonInvite()
            elif rx_update.search(request_uri):
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                if request_uri == "SIP/2.0 603 Decline":
                    who = self.data[3]
                    who2 = self.data[4]
                    if self.data[4][0] == "T":
                        if self.data[4][5] == "s":
                            start = who2.find("p:") + 2
                            end = who2.find("@")
                        else:
                            start = who2.find("\"") + 1
                            end = who2.find("\" <")

                        user1 = who2[start:end]
                    elif self.data [3][0] == "T":
                        if self.data[3][5] == "s":
                            start = who.find("p:") + 2
                            end = who.find("@")
                        else:
                            start = who.find("\"") + 1
                            end = who.find("\" <")

                        user1 = who[start:end]

                    logging.info("%s     %s Rejected call\n",self.data[5],user1)

                self.processCode()
            else:
                logging.error("request_uri %s" % request_uri)
                print("message %s unknown" % self.data)

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0].decode("utf-8")
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            if rx_register.search(request_uri):
                who = self.data[2]
                start1 = who.find("\"") + 1
                end1 = who.find("\" <")
                user1 = who[start1:end1]
                logging.info("---REGISTRATION---      %s asking for registration   >>>   PROXY",user1)

            if rx_invite.search(request_uri):
                print("Call started : ")
                print(datetime.datetime.now().time())
                who = self.data[2]
                who2 = self.data[3]
                if self.data[3][4] == "s":
                    start2 = who2.find("p:") + 2
                    end2 = who2.find("@")
                else:
                    start2 = who2.find("\"") + 1
                    end2 = who2.find("\" <")

                start1 = who.find("\"") + 1
                end1 = who.find("\" <")
                user1 = who[start1:end1]
                user2 = who2[start2:end2]
                logging.info("%s     %s is calling to %s",self.data[5],user1, user2)

            else:
                #logging.info(">>> %s" % request_uri)
                logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
                logging.debug("Received from %s:%d" % self.client_address)

            self.processRequest()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")


