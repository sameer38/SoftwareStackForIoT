import os
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

gauth = GoogleAuth()

gauth.LoadCredentialsFile("mycreds.txt")
if gauth.credentials is None:
    # Authenticate if they're not there
    gauth.LocalWebserverAuth()
elif gauth.access_token_expired:
    # Refresh them if expired
    gauth.Refresh()
else:
    # Initialize the saved creds
    gauth.Authorize()
# Save the current credentials to a file
gauth.SaveCredentialsFile("mycreds.txt")

drive = GoogleDrive(gauth)

def upload_file(local_data_folder, folder_name_drive, file_name):
    folder_id = '-1'
    fileList = drive.ListFile({"q" : "'root' in parents and trashed=false"}).GetList()

    for file in fileList:
        if(file['title'] == folder_name_drive):
            folder_id = file['id']
            break

    if folder_id == '-1':
        file_metadata = {
            'name': folder_name_drive,
            'parents': 'root',
            'mimeType': 'application/vnd.google-apps.folder'
        }
        
        folder = drive.CreateFile(file_metadata)
        folder['title'] = folder_name_drive
        folder.Upload()

        folder_id = folder['id']
        print(f"creation of folder [{folder_name_drive}] successful.")
    
    file = drive.CreateFile({'parents' : [{'id' : folder_id}]})
    file.SetContentFile(os.getcwd() + '/' + local_data_folder + '/' + file_name)
    file['title'] = file_name
    file.Upload()
    file_id = file['id']
    print(f"File [{file_name}] with id [{file_id}] uploaded successfully.")

def batch_upload_file(local_data_folder, folder_name_drive):
    folder_id = '-1'
    fileList = drive.ListFile({"q" : "'root' in parents and trashed=false"}).GetList()

    for file in fileList:
        if(file['title'] == folder_name_drive):
            folder_id = file['id']
            break

    if folder_id == '-1':
        file_metadata = {
            'name': folder_name_drive,
            'parents': 'root',
            'mimeType': 'application/vnd.google-apps.folder'
        }
        
        folder = drive.CreateFile(file_metadata)
        folder['title'] = folder_name_drive
        folder.Upload()

        folder_id = folder['id']
        print(f"creation of folder [{folder_name_drive}] successful.")

    for root, dir, files in os.walk(os.getcwd() + '/' + local_data_folder):
        for local_file in files:
            file = drive.CreateFile({'parents' : [{'id' : folder_id}]})
            file.SetContentFile(os.getcwd() + '/' + local_data_folder + '/' + local_file)
            file['title'] = local_file
            file.Upload()
            file_id = file['id']
            print(f"File [{local_file}] with id [{file_id}] uploaded successfully.")
    
    print('Batch upload successful.')


# fileList = drive.ListFile({"q" : "'root' in parents"}).GetList()  

# for file1 in fileList:
#     print('title: %s, id: %s' % (file1['title'], file1['id']))

upload_file('Demo', 'Software Stack for IoT', 'cam.py')

batch_upload_file('Demo', 'Batch upload')