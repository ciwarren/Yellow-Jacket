import Client
import statistics
from datetime import datetime
import time

def analyze_metric(name, metric):
    print(name)
    print(f'Average (ms):\t{str(statistics.mean(metric)/1000)}')
    print(f'Min (ms):\t{str(min(metric)/1000)}')
    print(f'Max (ms):\t{str(max(metric)/1000)}\n')


delta_authentication = []
delta_start_to_auth = []
delta_message = []
trials = 10

for n in range(1,trials+1):
    results = Client.main(f'Test {str(n)}')
    print(results)
    delta_authentication.append(results[0].microseconds)
    delta_start_to_auth.append(results[1].microseconds)
    delta_message.append(results[2].microseconds)
    time.sleep(3)
          
print(f'\n------------------------------------\nTest conducted with {str(trials)} trials\n')

analyze_metric('Authentication', delta_authentication)
analyze_metric('Start thru Authentication', delta_start_to_auth)
analyze_metric('Message', delta_message)