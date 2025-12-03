The files contained in this repo are the result of the CS 303 final project.

Details of the project can be found in the report "Network Intrusion Detection System Using Multiple Machine Learning Models"

The accompanying pcap network flows must be downloaded from the Canadian Institute of Cybersecurity University of New Brunswick website, found under Intrusion detection evaluation dataset (CIC-IDS2017).
Ideally, the convert.py file is not needed and the flows can be converted with full features by using the cicflowmeter tool provided by the institute, but network security concerns prevented my use.
If able to use the tool, there is no need to run the convert.py script


--------------------------------------------------------------------------------------------------------------------------------------------------

Scripts are run as follows (first install all packages contained in requirements.txt:



convert.py (if needed) on ALL days 

combine_days.py

train_supervised.py

train_unsupervised.py
hybrid_model.py
