import csv
import time
import os, sys
import pandas as pd
import numpy as np
import datetime 
import warnings
warnings.simplefilter(action = "ignore", category = FutureWarning)


def parse_datetime(x):   
    time, zone = x.split()
    x = datetime.datetime.strptime(time, "%d/%b/%Y:%H:%M:%S")
    return x



def read_parse(filename):
    print("parsing log file into a pandas dataframe")
    data = pd.read_csv(filename, sep=r'\n', engine='python',header=None,names=['raw'])
    data['ip_address'] = data['raw'].str.extract(r'^([^\s]+\s)', expand=True)
    data['time_stamp'] = data['raw'].str.extract(r'^.*\[(\d\d/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} -\d{4})]', expand=True)
    data['time_stamp_universal'] = data["time_stamp"].apply(parse_datetime)
    data['request'] = data['raw'].str.extract(r'"(?P<request>.*)"', expand=True)
    data['status'] = data['raw'].str.extract(r'^.*"\s+([^\s]+)', expand=True).astype(int)
    data['content_size'] = data['raw'].str.extract(r'^.*\s+(\d+)$', expand=True)
    data['content_size']=data['content_size'].fillna(int(0))
    data['content_size']=data['content_size'].astype(int)
    #del data['raw']
    print("finished creating dataframe ---> continue to feature analysis")
    return data

    
def feature_write(data):
    #feature 1
    #A simple groupby, count and sort from pandas
    print("writing feature 1 to hosts.txt")
    active_ip=data.groupby('ip_address').count().sort('time_stamp',ascending=False).head(10).reset_index()[["ip_address","time_stamp"]]
    active_ip["ip_address"]=active_ip["ip_address"].apply(lambda x: x.strip())
    active_ip.to_csv(sys.argv[2],header=None,index=None)
    print("finished writing feature")
    del active_ip
    
    #feature 2
    print("writing feature 2 to resources.txt")
    sorted_path=data.groupby(['request'],as_index=False).agg({'content_size': np.sum}).sort('content_size',ascending=False).head(10)
    sorted_path['resource'] =  sorted_path["request"].apply(lambda x: x.split(' ')[1])
    sorted_path.to_csv(sys.argv[3],header=None,columns=['resource'],index=None)
    print("finished writing feature")
    del sorted_path
    
    #feature3
    print("writing feature 3 to hours.txt")
    time_grouped=data.groupby("time_stamp",as_index=False).count()[['time_stamp','ip_address']]
    zone=time_grouped.head(1)["time_stamp"][0].split()[1]
    time_grouped['time_stamp_universal']=time_grouped['time_stamp'].apply(parse_datetime)
    time_grouped.index=time_grouped["time_stamp_universal"]
    traffic_every_hour = time_grouped.groupby(pd.TimeGrouper(freq='60Min')).aggregate(np.sum).sort('ip_address',ascending=False).head(10)
    traffic_every_hour["time_stamp"]=traffic_every_hour.index
    traffic_every_hour["time_stamp"]=traffic_every_hour["time_stamp"].apply(lambda x: x.strftime("%d/%b/%Y:%H:%M:%S") + " " + zone)
    traffic_every_hour.to_csv(sys.argv[4],header=None,columns=['time_stamp','ip_address'],index=None)
    print("finished writing feature")
    del time_grouped,traffic_every_hour
    
    
    #feature 4
    print("writing feature 4 to blocked.txt")
    data.index=data["ip_address"]
    temp_group = data.groupby(["time_stamp_universal","ip_address","status"]).count()["request"]
    temp_group = temp_group.reset_index();temp_group.index= temp_group["time_stamp_universal"]
    temp_group = temp_group.groupby([pd.TimeGrouper("20S"),"ip_address","status"]).sum()
    temp_group = temp_group.reset_index()
    #Assuming only 401 status is login failure as mentioned in the challenge - "failed login (HTTP reply code of 401)"
    temp_group = temp_group[(temp_group["request"]>=3) & (temp_group["status"]==401)] #All ip that have 3 or more 401 status in under 20 sec
    #now lets check for 401 errors in sequence and collect them in a list easy to concat later and write
    temp_group = temp_group.reset_index(drop=True)
    collect_blocked_data=[]
    for j in range(len(temp_group)):
        temp = data.loc[temp_group.ip_address[j]]
        temp = temp.reset_index(drop=True)
        counter=0
        for i in range(len(temp)):
            if temp.status[i] == 401:
                counter += 1
                if counter > 3:
                    temp.index = temp.time_stamp_universal
                    collect_blocked_data.append(temp.loc[temp["time_stamp_universal"][i]:temp["time_stamp_universal"][i]+datetime.timedelta(seconds=300)]) #5min of blocked requests
    #overwrite the previous df to save memory
    temp_group=pd.concat(collect_blocked_data)
    temp_group.to_csv(sys.argv[5],header=None,columns=['raw'],index=None,quoting=csv.QUOTE_NONE,escapechar="~")
    print("finished writing final feature")
    del temp_group,collect_blocked_data

def main():
    feature_write(read_parse(sys.argv[1]))

if __name__ == "__main__":
    start_time = time.time()
    main()
    print("finsihed executing in %s seconds" % (time.time() - start_time))
