#!/bin/bash
#SBATCH --job-name=aes_chaos_randomness
#SBATCH --partition=thesis             
#SBATCH --nodes=1                        
#SBATCH --ntasks=1                       
#SBATCH --cpus-per-task=8                
#SBATCH --mem=30G                        
#SBATCH --time=8:00:00                  
#SBATCH --output=risultati_%j.out        
#SBATCH --error=errori_%j.err            

# Load the necessary modules
cd $SLURM_SUBMIT_DIR

# Launch the Python script to run the tests
python3 runNistTest.py