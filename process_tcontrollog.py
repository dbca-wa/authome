import sys
import os
import re
import json

record_re = re.compile("\\n(?P<runtime>[0-9]{4}\\-[0-9]{2}\\-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}).+Buckets of tcontrol: buckets=(?P<bucketsdata>\\[([0-9]+(\\s*\\,\\s*[0-9]+)*)?\\]).*begintime=(?P<bucketsbegintime>(None|[0-9]{4}\\-[0-9]{2}\\-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6})).*fetchtime=(?P<fetchtime>(None|[0-9]{4}\\-[0-9]{2}\\-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}))",re.IGNORECASE|re.DOTALL)

def readrecord(instream):
    record_started = False
    record = ""

    line = instream.readline()
    while line:
        if record_started:
            record = "{}{}".format(record,line)
            if line.strip() == "====END====":
                m = record_re.search(record)
                if not m:
                    raise Exception("Failed to parse record:{}".format(record))
                key = ["0000-00-00 00:00:00.000000" if m.group("bucketsbegintime") == "None" else m.group("bucketsbegintime"),"0000-00-00 00:00:00.000000" if m.group("fetchtime") == "None" else m.group("fetchtime"),m.group("runtime"),json.loads(m.group("bucketsdata"))]
                return (key,record)
        elif line.strip() == "====BEGIN====":
            record_started = True
            record = line

        line = instream.readline()

    return (None,None)

def sortfiledata(infile,outfile):
    key = ""
    record = ""
    firstrecord = True
    records = []
    last_savedkey = None
    misorderedrecords = 0
    buffersize = 10000
    writebatchsize = 100
    counter = 0
    writercounter = 0
    misorderedfile = "/tmp/__auth2_tcontroldata_misordered.log"


    with open(misorderedfile,'w') as misorderedstream:
        with open(outfile,'w') as outstream:
            with open(infile,'r') as instream:
                #parse file
                while True:
                    key,record = readrecord(instream)
                    if not key:
                        break
                    records.append([key,record])
                    counter += 1
                    if len(records) >= buffersize:
                        records.sort(key=lambda d:d[0])
                        #save the first 100 records
                        for i in range(writebatchsize):
                            if last_savedkey and last_savedkey > records[0][0]:
                                misorderedrecords += 1
                                misorderedstream.write(records[0][1])
                            else:
                                if firstrecord:
                                    firstrecord = False
                                else:
                                    outstream.write("\n")
                                writercounter += 1
                                outstream.write(records[0][1])
                                last_savedkey = records[0][0]
                            del records[0]
                        if counter % 1000 == 0:
                            print("Processed {} records, {} records are written, found {} misordered records".format(counter,writercounter,misorderedrecords))

            #process the datas in buffer
            records.sort(key=lambda d:d[0])
            for record in records:
                if last_savedkey and last_savedkey > record[0]:
                    misorderedrecords += 1
                    misorderedstream.write(record[1])
                else:
                    if firstrecord:
                        firstrecord = False
                    else:
                        outstream.write("\n")
                    writercounter += 1
                    outstream.write(record[1])
                    last_savedkey = record[0]

            records.clear()

            print("Processed {} records, {} records are written, found {} misordered records".format(counter,writercounter,misorderedrecords))

    if not misorderedrecords:
        return

    #process the misordered records
    print("Found {} misordered records".format(misorderedrecords))
    key = ""
    record = ""
    firstrecord = True

    misorderedrecord = ""
    misorderedkey = ""

    tmpoutfile = "{}.tmp".format(outfile)
    os.rename(outfile,tmpoutfile)
    with open(outfile,'w') as outstream:
        with open(tmpoutfile,'r') as instream:
            with open(misorderedfile,'r') as misorderedstream:
                #parse file
                while True:
                    key,record = readrecord(instream)
                    if not key:
                        break
                    #save the misordered records if have
                    while True:
                        if not misorderedkey:
                            misorderedkey,misorderedrecord = readrecord(misorderedstream)

                        if not misorderedkey:
                            break

                        if key > misorderedkey:
                            if firstrecord:
                                firstrecord = False
                            else:
                                outstream.write("\n")
                            outstream.write(misorderedrecord)
                            misorderedkey = None
                            misorderedrecord = None
                        else:
                            break
    
                    if firstrecord:
                        firstrecord = False
                    else:
                        outstream.write("\n")
                    outstream.write(record)

                #write the remaining misordered records
                while True:
                    if not misorderedkey:
                        misorderedkey,misorderedrecord = readrecord(misorderedstream)

                    if not misorderedkey:
                        break

                    if firstrecord:
                        firstrecord = False
                    else:
                        outstream.write("\n")
                    outstream.write(misorderedrecord)
                    misorderedkey = None
                    misorderedrecord = None
    #remote the tmp file
    os.remove(tmpoutfile)

def combinefiles(infiles,outfile):
    firstrecord = True
    with open(outfile,'w') as outstream:
        try:
            instreams = []
            #open file stream, and read the first line
            for f in files:
                instreams.append([open(f),None,None])
                instreams[-1][1],instreams[-1][2] = readrecord(instreams[-1][0])
            while True:
                #find the smaller key
                smallerstream = None
                for instream in instreams:
                    if not instream[1]:
                        #no more record
                        continue
                    elif not smallerstream:
                        smallerstream = instream
                    elif smallerstream[1] > instream[1]:
                        smallerstream = instream

                if not smallerstream:
                    break

                if firstrecord:
                    firstrecord = False
                else:
                    outstream.write("\n")
                outstream.write(smallerstream[2])
                smallerstream[1],smallerstream[2] = readrecord(smallerstream[0])
        finally:
            #close instreams
            for i in instreams:
                if i[0]:
                    try:
                        i[0].close()
                    except:
                        pass



if __name__ == '__main__':
    if len(sys.argv) == 1:
        infiles = ["./logs/auth2_8070.log"]
        outfiles = ["./logs/auth2_8070_sorted.log"]
    elif len(sys.argv) == 2:
        infiles = sys.argv[1]
        infiles = [f.strip() for f in infiles.split(",") if f.strip()]
        outfiles = []
        for f in infiles:
            if "." in f:
                outfiles.append("{}_sorted.{}".format(*f.rsplit(".",1)))
            else:
                outfiles.append("{}_sorted".format(f))
    for i in range(len(infiles)):
        sortfiledata(infiles[i],outfiles[i])

    if len(outfiles) > 1:
        #combine the files
        folder, name = os.path.split(outfiles[0])
        combinedfile = os.path.join(folder,"tcontroldata_combined.log")
        combinefiles(outfiles,combinedfile)
        print("Please check the outfile({}) for ordered traffic control data".format(combinedfile))
    else:
        print("Please check the outfile({}) for ordered traffic control data".format(outfiles[0]))

