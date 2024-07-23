def scan_IOC(self, row):    
        ThreatActorName = row['Threat Actor Name'] 
        IndicatorOfCompromise = row['IOC Value'].strip() 
        IOC_type = row['IOC Type']
        api_key = row['API']

        md5_hash, sha1_hash, sha256_hash = "", "", ""
        domain_communicating_files_result = []
        domain_referrer_files_result = []
        malicous_vendors_count = 0

        if IOC_type in ['MD5', 'SHA1', 'SHA256']:
            status, md5_hash, sha1_hash, sha256_hash, malicous_vendors_count = self.check_IOC_hash(IndicatorOfCompromise, api_key)
            # Writing Data to Python List        
        if md5_hash != "" and sha1_hash != "" and sha256_hash != "":
            datetime_text = datetime.now().strftime(f"%d-%m-%Y")
            data_list = [{
                "Date": datetime_text,
                "Threat Actor Name": ThreatActorName,
                "Parent IOC Value": "",
                "Referral IOC Type": "",
                "Referral IOC Value": "",
                "IOC Value": md5_hash,
                "IOC Type": "MD5",
                "Status": status,
                "No of vendors flagged as malicious": malicous_vendors_count
            }, {
                "Date": datetime_text,
                "Threat Actor Name": ThreatActorName,
                "Parent IOC Value": "",
                "Referral IOC Type": "",
                "Referral IOC Value": "",                
                "IOC Value": sha1_hash,
                "IOC Type": "SHA1",
                "Status": status,
                "No of vendors flagged as malicious": malicous_vendors_count
            }, {
                "Date": datetime_text,
                "Threat Actor Name": ThreatActorName,
                "Parent IOC Value": "",
                "Referral IOC Type": "",
                "Referral IOC Value": "",                
                "IOC Value": sha256_hash,
                "IOC Type": "SHA256",
                "Status": status,
                "No of vendors flagged as malicious": malicous_vendors_count
            }]
        else:
            datetime_text = datetime.now().strftime(f"%d-%m-%Y")
            data_list = [{
                "Date": datetime_text,
                "Threat Actor Name": ThreatActorName,
                "Parent IOC Value": "",
                "Referral IOC Type": "",
                "Referral IOC Value": "",                
                "IOC Value": IndicatorOfCompromise,
                "IOC Type": IOC_type,
                "Status": status,
                "No of vendors flagged as malicious": malicous_vendors_count
            }]
        data_list.extend(domain_communicating_files_result)
        data_list.extend(domain_referrer_files_result)
        df = pd.DataFrame(data_list)
        self.write_data_to_csv(self.Master_CSV_filename, df)
        time.sleep(15)   # As Rate Limit for Free API is FOUR PER Minute  (60/4 == 15)

    def compare_final_data_with_archive(self):
        self.printer(f"{Fore.YELLOW}Comparing {Fore.GREEN}Sorted Master Excel{Fore.YELLOW} with {Fore.GREEN}Archive Excel{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        final_archive_ioc_list = []
        df = pd.read_excel(self.archive_excel_file)
        df = df['IOC Value']

        for _, ioc in df.items():
            final_archive_ioc_list.append(ioc.replace('[.]', '.'))

        # Reading Sorted CSV for Deletion of Unwanted IOC (Need to delete IOCs which are already there is Archive)
        IOC_df = pd.read_csv(self.Sorted_Master_CSV_filename)
        for archive_ioc in final_archive_ioc_list:
            index_names = IOC_df[IOC_df['IOC Value'] == archive_ioc].index
            IOC_df.drop(index_names, inplace=True)

        reffer_ioc_df = IOC_df.loc[IOC_df['Parent IOC Value'].notnull()]  # Making a df of Communicating/Reffer files
        reffer_ioc_df = reffer_ioc_df.loc[:, ["Date", "Threat Actor Name", "Parent IOC Value", "Referral IOC Type", "Referral IOC Value", "IOC Type", "Status"]]

        self.printer(f"{Fore.YELLOW}Removing {Fore.GREEN}Duplicates{Fore.YELLOW} ...{Style.RESET_ALL}", "INFO")
        IOC_Value_column_name = 'IOC Value'
        IOC_df = IOC_df.drop_duplicates(subset=IOC_Value_column_name, keep='first')

        # Removing Any Row whose Value is CSV Header
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Date'] == 'Date'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Threat Actor Name'] == 'Threat Actor Name'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['IOC Value'] == 'IOC Value'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['IOC Type'] == 'IOC Type'].index)
        IOC_df = IOC_df.drop(IOC_df[IOC_df['Status'] == 'Status'].index)

        # Adding the new column to the "Not covered" sheet
        DF_Which_NEED_TO_SEND = IOC_df[IOC_df['Status'] == 'McAfee Not Detected']
        DF_Which_NEED_TO_SEND = DF_Which_NEED_TO_SEND.loc[:, ["Date", "Threat Actor Name", "IOC Value", "IOC Type", "Status", "No of vendors flagged as malicious"]]

        writer = pd.ExcelWriter(self.Threat_Intel_Report_filename + datetime.now().strftime('_%d-%m-%Y_%H_%M_%S') + ".xlsx", engine='xlsxwriter')
        # Add a header format.
        workbook = writer.book
        header_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'fg_color': '#7bb8ed',
            'border': 1})

        DF_Which_NEED_TO_SEND.to_excel(writer, sheet_name='Not covered', index=False)
        worksheet = writer.sheets['Not covered']

        # Header formatting
        for col_num, value in enumerate(DF_Which_NEED_TO_SEND.columns.values):
            worksheet.write(0, col_num, value, header_format)
            column_len = DF_Which_NEED_TO_SEND[value].astype(str).str.len().max()
            column_len = max(column_len, len(value)) + 3
            worksheet.set_column(col_num, col_num, column_len)
        writer._save()

        writer = pd.ExcelWriter(self.After_Comparison_With_Archive_New_Filename + datetime.now().strftime('_%d-%m-%Y_%H_%M_%S') + ".xlsx", engine='xlsxwriter')

        # Add a header format.
        workbook = writer.book
        header_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'fg_color': '#7bb8ed',
            'border': 1})
        for excel_sheet_name in ['FireEye Not Detected', 'Not Found', 'Clean', 'Malicious']:
            temp_df = IOC_df.loc[IOC_df['Status'] == excel_sheet_name]
            temp_df = temp_df.loc[:, ["Date", "Threat Actor Name", "IOC Value", "IOC Type", "Status"]]
            temp_df = temp_df.loc[temp_df['IOC Value'].notnull()]  # IOC Value will be NaN if it is part of 'Referral IOCs'
            if excel_sheet_name == 'FireEye Not Detected':
                excel_sheet_name = 'Not Covered'
            temp_df.to_excel(writer, sheet_name=excel_sheet_name, index=False)
            worksheet = writer.sheets[excel_sheet_name]
            # Header formatting
            for col_num, value in enumerate(temp_df.columns.values):
                worksheet.write(0, col_num, value, header_format)
                column_len = temp_df[value].astype(str).str.len().max()
                column_len = max(column_len, len(value)) + 3
                worksheet.set_column(col_num, col_num, column_len)
        reffer_ioc_df.to_excel(writer, sheet_name="Referral IOCs", index=False)
        worksheet = writer.sheets["Referral IOCs"]
        # Header formatting for Referral IOCs
        for col_num, value in enumerate(reffer_ioc_df.columns.values):
            worksheet.write(0, col_num, value, header_format)
            column_len = reffer_ioc_df[value].astype(str).str.len().max()
            column_len = max(column_len, len(value)) + 3
            worksheet.set_column(col_num, col_num, column_len)
        writer._save()
