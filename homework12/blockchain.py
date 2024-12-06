from hashlib import sha256

values_to_save = [91911, 90954, 95590, 97390, 96578, 97211, 95090]
x = 5 # number of zeros in hash
blockchain_result_filename = "blockchain.txt"


# our blockchain block as class
# Why? Because I'm Java dev & I love classes
class BC_block:
  data = ""
  prev_hash = ""
  nonce = None
  hash = None

  # constructor
  def __init__(self, *args):
    if len(args) == 2:
      self.data = args[0]
      self.prev_hash = args[1]
    elif len(args) == 0:
      # init genesis_block
      self.data = []
      self.data = "genesis_block"
      self.prev_hash = "genesis_block"
      self.nonce = x  # idk, let it be x
      self.generate_hash()
      self.hash = ("0" * x) + self.hash[:-x]

  # generates hash, returns true if valid hash, false if not
  def generate_hash(self):
    if not self.nonce:
      print("(!) nonce is not set")
      return False

    str = f"{self.data}{self.prev_hash}{self.nonce}"
    self.hash = sha256(str.encode('utf-8')).hexdigest()

    if self.hash[:x] == "0"*x: # "00000......" ?
      return True
    return False

  def to_string(self):
    str = "---------- \n"
    str += f"data: {self.data} \n"
    str += f"prev_hash: {self.prev_hash} \n"
    str += f"nonce: {self.nonce} \n"
    str += f"hash: {self.hash} \n"
    return str






blockchain = []

def add_block(block):
  blockchain.append(block)

def mine_block(block):
  block.nonce = 1
  while not block.generate_hash(): # yes, i do not care if it's an infinite cycle
    block.nonce = block.nonce + 1

def write_file(name, data):
  with open(name, 'a') as file:
    file.writelines(data)






genesis_block = BC_block()
add_block(genesis_block)

print(genesis_block.to_string())

for val in values_to_save:
  print(f"mining nonce for val={val}")
  prev_hash = blockchain[-1].hash
  new_block = BC_block(val, prev_hash)
  mine_block(new_block)
  print(new_block.to_string())
  add_block(new_block)


for block in blockchain:
  write_file(blockchain_result_filename, block.to_string())







