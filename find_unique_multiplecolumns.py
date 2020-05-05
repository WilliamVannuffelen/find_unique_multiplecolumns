#!/usr/bin/env python3
import os, sys
import logging
import pandas as pd
from pathlib import Path
from datetime import datetime
from argparse import ArgumentParser

# FUNCTION DEFINITIONS
# helper function to recurse through directories
def _scantree(input_path):
    for entry in os.scandir(input_path):
        if entry.is_dir(follow_symlinks=False):
            yield from _scantree(entry.path)
        else:
            yield entry

# find input files from source dir
def get_inputfiles(input_path):
    input_files = []
    try:
        for entry in _scantree(input_path):
            if entry.path.endswith('.csv'):
                input_files.append(entry)
        log.info("Found {0} CSV files containing input data.".format(len(input_files)))
    except FileNotFoundError as e:
        log.error("Input directory does not exist. Terminating.")
        log.error("{0} - {1}".format(type(e).__name__, e.filename))
        terminate_script(1)
    except Exception as e:
        log.error("Unexpected error while finding input files. Terminating.")
        log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
        terminate_script(1)
    
    return input_files

# read and concat all csv contents to single dataframe
def load_data(input_files):
    dfs = []
    for f in input_files:
        try:
            df = pd.read_csv(f.path)
            dfs.append(df)
        except pd.errors.EmptyDataError as e:
            log.warn("Failed to read file content as CSV: {0}".format(f.path))
        except Exception as e:
            log.error("Unexpected error while reading CSV data. Terminating.")
            log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
            terminate_script(1)
    try:
        df = pd.concat(dfs)
        log.info("Concatenated {0:,} records into a dataframe for analysis.".format(len(df.index)))
    except ValueError as e:
        if e.args[0] == "No objects to concatenate":
            log.info("No data found in any selected CSV file. This is not an error. Terminating.")
            terminate_script(0)
        else:
            log.error("Unexpected error while concatenating data. Terminating.")
            log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
            terminate_script()
    except Exception as e:
        log.error("Unexpected error while concatenating data. Terminating.")
        log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
        terminate_script(1)

    return df

# drop duplicate entries from dataframe
def drop_duplicates(df):
    try:
        df = df.drop_duplicates(['ipAddress','hostName','user'])
        log.info("Dropped duplicate records. There are {0} unique records remaining.".format(len(df.index)))
    except Exception as e:
        log.error("Unexpected error while dropping duplicate entries from dataframe. Terminating.")
        log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
        terminate_script(1)
    return df

def export_dataframe(df):
    try:
        df.to_csv(output_path)
        log.info("Exported dataframe to CSV file: {0}".format(output_path))
    except Exception as e:
        log.error("Unexpected error while exporting data to CSV. Terminating.")
        log.error("{0} - {1}".format(type(e).__name__, e.args), exc_info=True)
        terminate_script(1)

def terminate_script(exit_code):
    if exit_code == 0:
        exit_code = "Clean exit."
    elif exit_code == 1:
        exit_code = "Fatal error."

    end_time = datetime.now()
    time_delta = end_time - start_time
    log.info("Script ended. Reason: {0} Total runtime: {1}.".format(exit_code, time_delta))
    sys.exit()

# ARGUMENT PROCESSING
parser = ArgumentParser()

parser.add_argument("-p", "--path",
                    type=str,
                    default=Path(os.getcwd()),
                    help="Full directory path of input files. Default is pwd.")
parser.add_argument("-o", "--output",
                    type=str,
                    default=Path(os.getcwd()),
                    help="Full directory path of target output file. Default is pwd.")
parser.add_argument("-l", "--log",
                    type=str,
                    default=Path(os.getcwd()),
                    help="Full directory path of target log file. Default is pwd.")

args = parser.parse_args()
input_path = Path(args.path)
output_dir_path = Path(args.output)
log_dir_path = Path(args.log)

output_path = output_dir_path / "{0}_insecure_ldap_binds_unique.csv".format(input_path.name)
log_path = log_dir_path / "{0}_insecure_ldap_binds_{1}.log".format(input_path.name, datetime.now().strftime("%Y-%m-%d_%H_%M"))

# FUNCTION CALLS
if __name__ == '__main__':
    start_time = datetime.now()

    # init logger
    log = logging.getLogger()
    logging.basicConfig(filename = log_path,
                        level = logging.INFO,
                        format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log.info("Script started.")
    input_files = get_inputfiles(input_path)
    df = load_data(input_files)
    df = drop_duplicates(df)
    export_dataframe(df)
    terminate_script(0)