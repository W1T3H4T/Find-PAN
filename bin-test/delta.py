# Function to calculate Delta Percent
def delta_percent(first, second):
    if first > second:
        change = first - second 
        delta = ( change / second ) * 100
        return round(delta, 2)  # Round to two decimal places for percentage
    elif second > first:
        change = second - first
        delta = ( change / first ) * 100
        return round(delta * -1, 2)  # Round to two decimal places for percentage
    else:
        raise ValueError("Both pre and post-observation times must be positive.")

# Example usage
pre_run_time = 5  # Pre-change run time in seconds
post_run_time = 1   # Post-change run time in seconds
delta_percent = delta_percent(pre_run_time, post_run_time)
print("Delta percent change: {}%".format(delta_percent))
