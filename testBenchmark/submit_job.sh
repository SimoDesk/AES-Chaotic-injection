#!/bin/bash
#SBATCH --job-name=aes_chaos_benchmark
#SBATCH --partition=thesis             
#SBATCH --nodes=1                        
#SBATCH --ntasks=1                       
#SBATCH --cpus-per-task=8                
#SBATCH --mem=30G                        
#SBATCH --time=8:00:00                  
#SBATCH --output=risultati_%j.out        
#SBATCH --error=errori_%j.err            

#SBATCH --mail-type=END,FAIL
#SBATCH --mail-user=descontus.2116496@studenti.uniroma1.it

# Load the necessary modules
cd $SLURM_SUBMIT_DIR

# Launch the Python script to run the tests
python3 runBenchmark.py --time-only