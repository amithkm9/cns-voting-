"""
Secure Voting System Using Elliptic Curve Cryptography (ECC)

This implementation includes:
- ECC key generation
- Vote encryption and decryption
- Digital signatures for vote verification
- Voter authentication
- Vote casting and counting
- Prevention of duplicate voting
"""

import os
import json
import time
import base64
import hashlib
import secrets
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict, field

# Cryptography libraries
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.exceptions import InvalidSignature


# ==================== Data Models ====================

@dataclass
class Voter:
    voter_id: str
    name: str
    public_key_pem: str
    # Private key is stored securely in a separate file in a real system
    # Here we store it for demo purposes only
    private_key_pem: str
    has_voted: bool = False
    
    def to_dict(self) -> dict:
        # Exclude private key from the public representation
        return {
            "voter_id": self.voter_id,
            "name": self.name,
            "public_key_pem": self.public_key_pem,
            "has_voted": self.has_voted
        }


@dataclass
class Candidate:
    candidate_id: str
    name: str
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EncryptedVote:
    voter_id: str
    encrypted_data: bytes
    signature: bytes
    timestamp: float
    
    def to_dict(self) -> dict:
        return {
            "voter_id": self.voter_id,
            "encrypted_data": base64.b64encode(self.encrypted_data).decode('utf-8'),
            "signature": base64.b64encode(self.signature).decode('utf-8'),
            "timestamp": self.timestamp
        }


@dataclass
class Election:
    election_id: str
    title: str
    candidates: List[Candidate]
    voters: Dict[str, Voter] = field(default_factory=dict)
    encrypted_votes: List[EncryptedVote] = field(default_factory=list)
    vote_counts: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "election_id": self.election_id,
            "title": self.title,
            "candidates": [c.to_dict() for c in self.candidates],
            "voters": {v_id: v.to_dict() for v_id, v in self.voters.items()},
            "encrypted_votes": [v.to_dict() for v in self.encrypted_votes],
            "vote_counts": self.vote_counts
        }


# ==================== Cryptographic Utilities ====================

class ECCCrypto:
    def __init__(self):
        # Use SECP256R1 curve for better security
        self.curve = ec.SECP256R1()
        
    def generate_key_pair(self) -> Tuple[str, str]:
        """Generate ECC key pair and return PEM-encoded strings."""
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        
        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def load_private_key(self, private_key_pem: str) -> ec.EllipticCurvePrivateKey:
        """Load a private key from PEM format."""
        return load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
    
    def load_public_key(self, public_key_pem: str) -> ec.EllipticCurvePublicKey:
        """Load a public key from PEM format."""
        return serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
    
    def derive_shared_key(self, private_key_pem: str, public_key_pem: str) -> bytes:
        """Derive a shared secret using ECDH."""
        private_key = self.load_private_key(private_key_pem)
        public_key = self.load_public_key(public_key_pem)
        
        # Perform key exchange
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'voting-system-encryption'
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_vote(self, vote_data: str, private_key_pem: str, recipient_public_key_pem: str) -> bytes:
        """Encrypt vote data using hybrid encryption (ECDH + AES-GCM)."""
        # Derive a shared secret
        shared_key = self.derive_shared_key(private_key_pem, recipient_public_key_pem)
        
        # Generate a random IV (nonce)
        iv = os.urandom(12)
        
        # Encrypt the vote data
        encryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv)
        ).encryptor()
        
        ciphertext = encryptor.update(vote_data.encode('utf-8')) + encryptor.finalize()
        
        # Combine IV, tag, and ciphertext
        return iv + encryptor.tag + ciphertext
    
    def decrypt_vote(self, encrypted_data: bytes, private_key_pem: str, sender_public_key_pem: str) -> str:
        """Decrypt vote data using the shared key."""
        # Derive the same shared secret
        shared_key = self.derive_shared_key(private_key_pem, sender_public_key_pem)
        
        # Extract IV and tag
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Decrypt
        decryptor = Cipher(
            algorithms.AES(shared_key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    
    def sign_data(self, data: bytes, private_key_pem: str) -> bytes:
        """Create a digital signature for the given data."""
        private_key = self.load_private_key(private_key_pem)
        
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Verify a digital signature."""
        public_key = self.load_public_key(public_key_pem)
        
        try:
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


# ==================== Voting System ====================

class VotingSystem:
    def __init__(self):
        self.crypto = ECCCrypto()
        self.elections: Dict[str, Election] = {}
        
        # Generate election authority's key pair
        self.authority_private_key, self.authority_public_key = self.crypto.generate_key_pair()
    
    def create_election(self, election_id: str, title: str, candidates: List[Tuple[str, str]]) -> Election:
        """Create a new election with specified candidates."""
        candidate_objects = [Candidate(cid, name) for cid, name in candidates]
        election = Election(election_id, title, candidate_objects)
        
        # Initialize vote counts
        for candidate in candidate_objects:
            election.vote_counts[candidate.candidate_id] = 0
            
        self.elections[election_id] = election
        return election
    
    def register_voter(self, election_id: str, voter_id: str, name: str) -> Voter:
        """Register a voter for an election and generate their key pair."""
        if election_id not in self.elections:
            raise ValueError(f"Election {election_id} does not exist")
            
        if voter_id in self.elections[election_id].voters:
            raise ValueError(f"Voter {voter_id} is already registered")
            
        # Generate voter's key pair
        private_key, public_key = self.crypto.generate_key_pair()
        
        # Create and store voter
        voter = Voter(voter_id, name, public_key, private_key)
        self.elections[election_id].voters[voter_id] = voter
        
        return voter
    
    def cast_vote(self, election_id: str, voter_id: str, candidate_id: str) -> bool:
        """Cast a vote for a candidate in the specified election."""
        # Validate inputs
        if election_id not in self.elections:
            raise ValueError(f"Election {election_id} does not exist")
            
        election = self.elections[election_id]
        
        if voter_id not in election.voters:
            raise ValueError(f"Voter {voter_id} is not registered for this election")
            
        voter = election.voters[voter_id]
        
        if voter.has_voted:
            raise ValueError(f"Voter {voter_id} has already cast a vote")
            
        candidate_exists = any(c.candidate_id == candidate_id for c in election.candidates)
        if not candidate_exists:
            raise ValueError(f"Candidate {candidate_id} does not exist in this election")
        
        # Create vote data
        vote_data = json.dumps({
            "election_id": election_id,
            "candidate_id": candidate_id,
            "timestamp": time.time()
        })
        
        # Encrypt the vote using the election authority's public key
        encrypted_data = self.crypto.encrypt_vote(
            vote_data, 
            voter.private_key_pem, 
            self.authority_public_key
        )
        
        # Sign the encrypted data
        signature = self.crypto.sign_data(encrypted_data, voter.private_key_pem)
        
        # Create and store the encrypted vote
        encrypted_vote = EncryptedVote(
            voter_id=voter_id,
            encrypted_data=encrypted_data,
            signature=signature,
            timestamp=time.time()
        )
        
        election.encrypted_votes.append(encrypted_vote)
        
        # Mark the voter as having voted
        voter.has_voted = True
        
        return True
    
    def count_votes(self, election_id: str) -> Dict[str, int]:
        """Count all votes in the specified election."""
        if election_id not in self.elections:
            raise ValueError(f"Election {election_id} does not exist")
            
        election = self.elections[election_id]
        
        # Reset vote counts
        for candidate in election.candidates:
            election.vote_counts[candidate.candidate_id] = 0
        
        # Process each encrypted vote
        rejected_votes = 0
        for encrypted_vote in election.encrypted_votes:
            voter_id = encrypted_vote.voter_id
            
            if voter_id not in election.voters:
                print(f"Warning: Vote from unregistered voter {voter_id}")
                rejected_votes += 1
                continue
                
            voter = election.voters[voter_id]
            
            # Verify the signature
            is_valid = self.crypto.verify_signature(
                encrypted_vote.encrypted_data,
                encrypted_vote.signature,
                voter.public_key_pem
            )
            
            if not is_valid:
                print(f"Warning: Invalid signature for vote from {voter_id}")
                rejected_votes += 1
                continue
            
            # Decrypt the vote
            try:
                decrypted_data = self.crypto.decrypt_vote(
                    encrypted_vote.encrypted_data,
                    self.authority_private_key,
                    voter.public_key_pem
                )
                vote_obj = json.loads(decrypted_data)
                
                # Verify the vote is for this election
                if vote_obj["election_id"] != election_id:
                    print(f"Warning: Vote for wrong election from {voter_id}")
                    rejected_votes += 1
                    continue
                
                candidate_id = vote_obj["candidate_id"]
                
                # Count the vote
                if candidate_id in election.vote_counts:
                    election.vote_counts[candidate_id] += 1
                else:
                    print(f"Warning: Vote for non-existent candidate {candidate_id}")
                    rejected_votes += 1
            
            except Exception as e:
                print(f"Error decrypting vote from {voter_id}: {str(e)}")
                rejected_votes += 1
        
        if rejected_votes > 0:
            print(f"Total rejected votes: {rejected_votes}")
            
        return election.vote_counts
    
    def get_election_results(self, election_id: str) -> List[Tuple[str, str, int]]:
        """Get formatted election results."""
        if election_id not in self.elections:
            raise ValueError(f"Election {election_id} does not exist")
            
        election = self.elections[election_id]
        
        # Count votes first
        self.count_votes(election_id)
        
        # Format results
        results = []
        for candidate in election.candidates:
            cid = candidate.candidate_id
            votes = election.vote_counts[cid]
            results.append((cid, candidate.name, votes))
            
        # Sort by vote count (descending)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results


# ==================== Command Line Interface ====================

class VotingSystemCLI:
    def __init__(self):
        self.voting_system = VotingSystem()
        self.current_election: Optional[str] = None
        self.current_voter: Optional[str] = None
    
    def display_header(self):
        """Display application header."""
        print("\n" + "=" * 60)
        print("       SECURE VOTING SYSTEM USING ECC CRYPTOGRAPHY")
        print("=" * 60)
    
    def display_menu(self):
        """Display main menu."""
        print("\nMAIN MENU:")
        print("1. Create Election")
        print("2. Register Voter")
        print("3. Voter Login")
        print("4. Cast Vote")
        print("5. Count Votes and Display Results")
        print("6. Exit")
        print("=" * 60)
    
    def create_election(self):
        """Create a new election."""
        print("\n=== CREATE NEW ELECTION ===")
        
        election_id = input("Enter election ID: ").strip()
        if not election_id:
            print("Election ID cannot be empty.")
            return
            
        title = input("Enter election title: ").strip()
        if not title:
            print("Election title cannot be empty.")
            return
        
        candidates = []
        
        while True:
            cid = input("Enter candidate ID (or leave empty to finish): ").strip()
            if not cid:
                break
                
            name = input(f"Enter name for candidate {cid}: ").strip()
            if not name:
                print("Candidate name cannot be empty.")
                continue
                
            candidates.append((cid, name))
        
        if not candidates:
            print("At least one candidate is required.")
            return
        
        try:
            election = self.voting_system.create_election(election_id, title, candidates)
            print(f"Election '{title}' created successfully with {len(candidates)} candidates.")
            self.current_election = election_id
        except Exception as e:
            print(f"Error creating election: {str(e)}")
    
    def register_voter(self):
        """Register a new voter for the current election."""
        if not self.current_election:
            print("No election selected. Please create an election first.")
            return
        
        print(f"\n=== REGISTER VOTER FOR ELECTION: {self.current_election} ===")
        
        voter_id = input("Enter voter ID: ").strip()
        if not voter_id:
            print("Voter ID cannot be empty.")
            return
            
        name = input("Enter voter name: ").strip()
        if not name:
            print("Voter name cannot be empty.")
            return
        
        try:
            voter = self.voting_system.register_voter(self.current_election, voter_id, name)
            print(f"Voter {name} registered successfully.")
            print(f"Generated ECC key pair for {voter_id}.")
            
            # In a real system, the private key would be securely transmitted to the voter
            # Here we just show it for demonstration purposes
            print("\nIMPORTANT: In a real system, the private key would be securely transmitted to the voter.")
            print(f"Public Key: {voter.public_key_pem[:64]}...")
            print(f"Private Key: {voter.private_key_pem[:64]}...")
        except Exception as e:
            print(f"Error registering voter: {str(e)}")
    
    def voter_login(self):
        """Simulate voter login."""
        if not self.current_election:
            print("No election selected. Please create an election first.")
            return
        
        print(f"\n=== VOTER LOGIN FOR ELECTION: {self.current_election} ===")
        
        voter_id = input("Enter your voter ID: ").strip()
        if not voter_id:
            print("Voter ID cannot be empty.")
            return
        
        election = self.voting_system.elections.get(self.current_election)
        if not election:
            print(f"Election {self.current_election} not found.")
            return
        
        voter = election.voters.get(voter_id)
        if not voter:
            print(f"Voter {voter_id} not registered for this election.")
            return
        
        print(f"Welcome, {voter.name}!")
        self.current_voter = voter_id
        
        if voter.has_voted:
            print("You have already cast your vote in this election.")
    
    def cast_vote(self):
        """Cast a vote for the logged-in voter."""
        if not self.current_election:
            print("No election selected. Please create an election first.")
            return
            
        if not self.current_voter:
            print("No voter logged in. Please login first.")
            return
        
        election = self.voting_system.elections.get(self.current_election)
        if not election:
            print(f"Election {self.current_election} not found.")
            return
        
        voter = election.voters.get(self.current_voter)
        if not voter:
            print(f"Voter {self.current_voter} not found.")
            return
        
        if voter.has_voted:
            print("You have already cast your vote in this election.")
            return
        
        print(f"\n=== CAST VOTE FOR ELECTION: {election.title} ===")
        print("Available candidates:")
        
        for i, candidate in enumerate(election.candidates, 1):
            print(f"{i}. {candidate.name} (ID: {candidate.candidate_id})")
        
        try:
            choice = int(input("\nEnter the number of your chosen candidate: "))
            if choice < 1 or choice > len(election.candidates):
                print("Invalid choice.")
                return
                
            candidate = election.candidates[choice - 1]
            
            print(f"You are about to vote for: {candidate.name}")
            confirm = input("Confirm your vote (yes/no): ").strip().lower()
            
            if confirm != 'yes':
                print("Vote cancelled.")
                return
            
            # Cast the vote
            result = self.voting_system.cast_vote(
                self.current_election,
                self.current_voter,
                candidate.candidate_id
            )
            
            if result:
                print("\nVote cast successfully!")
                print("Your vote has been encrypted, signed, and submitted.")
                print("The election authority will be able to verify and count your vote.")
            else:
                print("Failed to cast vote.")
        
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            print(f"Error casting vote: {str(e)}")
    
    def count_votes(self):
        """Count votes and display results."""
        if not self.current_election:
            print("No election selected. Please create an election first.")
            return
        
        election = self.voting_system.elections.get(self.current_election)
        if not election:
            print(f"Election {self.current_election} not found.")
            return
        
        print(f"\n=== ELECTION RESULTS: {election.title} ===")
        
        try:
            results = self.voting_system.get_election_results(self.current_election)
            
            total_votes = sum(count for _, _, count in results)
            print(f"Total votes cast: {total_votes}")
            
            print("\nCandidates by votes (descending):")
            print("-" * 50)
            print(f"{'Rank':<6}{'Candidate':<30}{'Votes':<10}{'Percentage':<15}")
            print("-" * 50)
            
            for i, (cid, name, votes) in enumerate(results, 1):
                percentage = (votes / total_votes * 100) if total_votes > 0 else 0
                print(f"{i:<6}{name:<30}{votes:<10}{percentage:.2f}%")
            
            print("-" * 50)
            
            # Determine winner
            if results and total_votes > 0:
                winner_id, winner_name, winner_votes = results[0]
                percentage = (winner_votes / total_votes * 100)
                
                print(f"\nWinner: {winner_name} with {winner_votes} votes ({percentage:.2f}%)")
            else:
                print("\nNo votes have been cast yet.")
                
        except Exception as e:
            print(f"Error counting votes: {str(e)}")
    
    def run(self):
        """Run the CLI application."""
        self.display_header()
        
        while True:
            self.display_menu()
            
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                self.create_election()
            elif choice == '2':
                self.register_voter()
            elif choice == '3':
                self.voter_login()
            elif choice == '4':
                self.cast_vote()
            elif choice == '5':
                self.count_votes()
            elif choice == '6':
                print("\nExiting Secure Voting System. Thank you!")
                break
            else:
                print("Invalid choice. Please try again.")


# ==================== Main Entry Point ====================

if __name__ == "__main__":
    try:
        cli = VotingSystemCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nProgram terminated by user. Exiting...")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")