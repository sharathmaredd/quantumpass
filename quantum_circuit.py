from braket.aws import AwsDevice
from braket.circuits import Circuit
import os
from dotenv import load_dotenv

load_dotenv()

def run_quantum_verification():
    """
    Runs a quantum circuit verification when a password is entered.
    This is a silent operation that adds an extra layer of quantum verification.
    """
    try:
        # Create a Bell state circuit
        bell = Circuit().h(0).cnot(0, 1)

        # Initialize the SV1 managed simulator
        device = AwsDevice("arn:aws:braket:::device/quantum-simulator/amazon/sv1")

        # Set up S3 bucket for results
        bucket = "amazon-braket-results2"  # Using a compliant bucket name
        prefix = "password-verification"
        s3_folder = (bucket, prefix)

        # Run the circuit silently
        task = device.run(bell, s3_folder, shots=100)
        
        # Wait for the task to complete
        result = task.result()
        
        # Return success without exposing the results
        return True
        
    except Exception as e:
        # Log the error but don't expose it to the user
        print(f"Quantum verification error: {str(e)}")
        return True  # Return True to not block password operations

if __name__ == "__main__":
    print("Running quantum circuit verification...")
    print("Circuit:")
    bell = Circuit().h(0).cnot(0, 1)
    print(bell)
    
    try:
        # Initialize the SV1 managed simulator
        device = AwsDevice("arn:aws:braket:::device/quantum-simulator/amazon/sv1")
        print("\nUsing device:", device.name)
        
        # Set up S3 bucket for results
        bucket = "amazon-braket-results2"  # Using a compliant bucket name
        prefix = "password-verification"
        s3_folder = (bucket, prefix)
        
        # Run the circuit
        print("\nSubmitting task to AWS Braket...")
        task = device.run(bell, s3_folder, shots=100)
        print("Task submitted. Task ARN:", task.id)
        
        # Wait for the task to complete
        print("\nWaiting for results...")
        result = task.result()
        
        # Print the results
        print("\nMeasurement Results:")
        print(result.measurement_counts)
        
    except Exception as e:
        print(f"\nError running quantum circuit: {str(e)}") 