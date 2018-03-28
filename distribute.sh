#/bin/bash

tunclient_name="simpletun/tunclient"
vms_folder_path="./vms"
server="$vms_folder_path/server"
client="$vms_folder_path/client"
helper_scripts_folder_path="./helper_scripts"

function copy_to_vms {
  file_to_copy=$1
  vms_path=$2
  cp $file_to_copy "$vms_path/$server"
  cp $file_to_copy "$vms_path/$client"
}

gcc -o $tunclient_name tunclient.c
copy_to_vms "$tunclient_name" "./"

cd simpletun
make clean
make all
copy_to_vms "simpletun" "../"
cd ..
