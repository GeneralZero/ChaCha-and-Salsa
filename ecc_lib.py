import random, math, secrets
from cryptopals_lib import is_prime, int_to_bytes, bytes_to_int, bXXencode

#Use Utility Math Functions

def _extended_euclidean_algorithm(a, b):
	"""
	Returns (gcd, x, y) s.t. a * x + b * y == gcd
	This function implements the extended Euclidean
	algorithm and runs in O(log b) in the worst case,
	taken from Wikipedia.
	"""
	old_r, r = a, b
	old_s, s = 1, 0
	old_t, t = 0, 1
	while r != 0:
		quotient = old_r // r
		old_r, r = r, old_r - quotient * r
		old_s, s = s, old_s - quotient * s
		old_t, t = t, old_t - quotient * t
	return old_r, old_s, old_t

def modinv(n, p):
	""" returns modular multiplicate inverse m s.t. (n * m) % p == 1 """
	gcd, x, y = _extended_euclidean_algorithm(n, p) # pylint: disable=unused-variable
	return x % p

def legendre_symbol(n, p):
	ls = pow(n, (p - 1) // 2, p)
	if ls == 1:
		return 1
	elif ls == p - 1:
		return -1
	else:
		# in case ls == 0
		raise Exception('n:{} = 0 mod p:{}'.format(n, p))

def check_sqrt(x, n, p):
	assert(pow(x, 2, p) == n % p)

def modular_sqrt(n:int, p:int) -> list:
	if type(n) != int or type(p) != int:
		raise TypeError('n and p must be integers')

	if p < 3:
		raise Exception('p must be equal to or more than 3')

	if not is_prime(p):
		raise Exception('p must be a prime number. {} is a composite number'.format(p))

	if legendre_symbol(n, p) == -1:
		raise Exception('n={} is Quadratic Nonresidue modulo p={}'.format(n, p))

	if p % 4 == 3:
		x = pow(n, (p + 1) // 4, p)
		check_sqrt(x, n, p)
		return [x, p - x]
	
	# Tonelli-Shanks
	q, s = p - 1, 0
	while q % 2 == 0:
		q //= 2
		s += 1
	z = 2
	while legendre_symbol(z, p) != -1:
		z += 1
	m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
	while t != 1:
		pow_t = pow(t, 2, p)
		for j in range(1, m):
			if pow_t == 1:
				m_update = j
				break
			pow_t = pow(pow_t, 2, p)
		b = pow(c, int(pow(2, m - m_update - 1)), p)
		m, c, t, r = m_update, pow(b, 2, p), t * pow(b, 2, p) % p, r * b % p
	check_sqrt(r, n, p)
	return [r, p - r]

def generate_KeyPair(point):
	#Generate a random intager 0 < N < Order
	random_priv_int = secrets.randbelow(point.curve.order)

	#Generate Public 
	public_point = random_priv_int * point

	return random_priv_int, public_point


class Point:
	def __init__(self, point_x, point_y, curve):
		self.curve = curve
		self.x = point_x
		self.y = point_y

		# The number of valid points in the group
		# Must get from definition
		#0 = self * order 

	def __str__(self):
		if self.isInifinityPoint():
			return f"{self.curve}: Infinity Point"
		else:
			return f"{self.curve}: x={self.x}, y={self.y}"

	def __repr__(self):
		return self.__str__()


	def __eq__(self, point2):
		return (
			self.curve.a == point2.curve.a and
			self.curve.b == point2.curve.b and
			self.curve.prime_mod == point2.curve.prime_mod and
			self.x == point2.x and 
			self.y == point2.y 
		)

	def isInifinityPoint(self):
		return (self.x == None and self.y == None)

	def __neg__(self):
		return self.curve.neg_point(self)

	def __add__(self, point2):
		return self.curve.add_point(self, point2)

	def __radd__(self, point2):
		return self.__add__(point2)

	def __sub__(self, point2):
		#Negate then add
		return self.__add__(- point2)

	def __mul__(self, scalar):
		return self.curve.mul_point(scalar, self)

	def __rmul__(self, scalar):
		return self.__mul__(scalar)

	def compressed(self):
		#Check which y value it represents
		is_odd = int_to_bytes((self.y % 2) + 2)
		# 0x02 || x if Even
		# 0x03 || x if odd
		return is_odd + int_to_bytes(self.x)

	def not_compressed(self):
		# 0x4 || x || y
		return 0x04 + int_to_bytes(self.x) + int_to_bytes(self.y)

	def decompress(self, binary_data):
		type_bit = binary_data[0]
		binary_data = binary_data[1:]

		#Check if be
		if type_bit == 0x02:
			#Is even
			x_point = bytes_to_int(binary_data)
			valid_y = self.curve.find_points_by_x(x_point)

			#Check which of the points are even and return
			for test_point in valid_y:
				if test_point % 2 == 0:
					return Point(curve=self.curve, point_x=x_point, point_y=test_point)

		elif type_bit == 0x03:
			#Is Odd
			x_point = bytes_to_int(binary_data)
			valid_y = self.curve.find_points_by_x(x_point)

			#Check which of the points are odd and return
			for test_point in valid_y:
				if test_point % 2 == 1:
					return Point(curve=self.curve, point_x=x_point, point_y=test_point)

		elif type_bit == 0x04:
			#Is Uncompressed
			x_point = bytes_to_int(binary_data[:len(binary_data)//2])
			y_point = bytes_to_int(binary_data[len(binary_data)//2:])
			return Point(curve=self.curve, point_x=x_point, point_y=y_point)

		else:
			raise Exception("Invalid Byte Data: Cannot Convert bytes into Point")


class Curve():
	def __init__(self, a, b, prime_mod, order=None, name=None):
		self.name = name
		self.a = a 
		self.b = b 
		self.prime_mod = prime_mod
		self.order = order
		#Generator Point

	def __str__(self):
		return self.name

	def __repr__(self):
		return self.__str__()

	def __eq__(self, other):
		return (
			self.a == other.a and 
			self.b == other.b and 
			self.prime_mod == other.prime_mod and
			self.order == other.order
		)

	def is_on_curve(self, point):
		#Check if the curve point is the same as the current curve
		if point.curve != self:
			return False
		return point.isInifinityPoint() or self._is_on_curve(point)

	def add_point(self, point1, point2):
		#Check if both points are on the curve
		if (not self.is_on_curve(point1)) or (not self.is_on_curve(point2)):
			raise ValueError("The points are not on the curve.")

		#Check if either are infinity points
		if point1.isInifinityPoint():
			return point2
		elif point2.isInifinityPoint():
			return point1

		#Check for other relation properties
		if point1 == point2:
			#Double Point because needs specific slope calculation
			return self._double_point(point1)
		if point1 == -point2:
			#Return Infinity point
			return Point(None, None, self)

		#Do Curve specific Point Addition
		return self._add_point(point1, point2)

	def double_point(self, point):
		if not self.is_on_curve(point):
			raise ValueError("The point is not on the curve.")
		if point.isInifinityPoint():
			#Return Infinity point
			return Point(None, None, self)

		#Do Curve Specific Point Addition
		return self._double_point(point)

	def mul_point(self, scalar, point):
		#Check if Point is on Curve
		if not self.is_on_curve(point):
			raise ValueError("The point is not on the curve.")

		#Check if point Provided is Infinity
		if point.isInifinityPoint():
			#Return Infinity point
			return Point(None, None, self)

		#Check if multipiled by Zero
		if scalar == 0:
			#Return Infinity point
			return Point(None, None, self)

		#Check if Scalar is negitive
		if scalar < 0:
			# Split the negitive Nultiplication into -1 * scalar
			# This allows the regular opperations then taking the negitive of the resulting point
			temp_scalar = -scalar
		else:
			temp_scalar = scalar


		#Initalize result to the Infinity point
		result = Point(None, None, self)
		temp_point = point

		while temp_scalar:
			#Check if current least significat bit is set
			# If set then add the inital point to the running total
			if temp_scalar & 0x1 == 1:
				result = temp_point + result

			#Increase the Point by 2 to be used if the bit is set
			temp_point = self.double_point(temp_point)

			#Decrease the scalor by 2 to check the next least significat
			temp_scalar >>= 1

		#Check if the scalar was negitive and invert the result
		if scalar < 0:
			return -result
		else:
			return result

	def neg_point(self, point):
		#Check if on curve
		if not self.is_on_curve(point):
			raise ValueError("The point is not on the curve.")
		if point.isInifinityPoint():
			#Return Infinity point
			return Point(None, None, self)

		#Do Normal Inverse of the point according to the specific curve
		return self._neg_point(point)


class ShortWeierstrassCurve(Curve):
	"""
	y^2 = x^3 + a*x + b
	https://en.wikipedia.org/wiki/Elliptic_curve
	"""

	def _is_on_curve(self, point1):
		# Do the same as findYOnCurve but test that the y that is generated from the formula is the same as y stored in the point.
		# y^2 = x^3 + a*x + b (mod p).
		# 0 = x^3 + a*x + b (mod p) - y^2
		test = (pow(point1.x, 3, self.prime_mod) + (point1.x * self.a) + self.b) % self.prime_mod

		#This has been shortened to test that both sides of the formula are zero. This removes the check for positve and negitive numbers
		return (test - (point1.y * point1.y)) % self.prime_mod == 0

	def _add_point(self, point1, point2):
		# Compute the slope using y2-y1/x2-x1. Using a mod inverse instead of division
		slope = (point2.y - point1.y) * modinv(point2.x - point1.x, self.prime_mod)

		#Compute the new X point
		# y = mx + d
		# d = y_1 - m(x_1)

		# y^2 = x^3 + a*x + b
		# b = (y_1)^2 - (x_1)^3 + x(x_1)

		# y^2 = (mx + d)^2 
		#     = m^2x^2 + 2mxd + d^2 
		#     = m^2x^2 + 2mx(y_1 - m(x_1)) + (y_1 - m(x_1))^2
		#     = x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2

		# Set the functions equal to each other and solve for zero
		# x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2 = x^3 + a*x + b
		# x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2 -x^3 - a*x - b = 0
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = 0

		#We know the roots of the equastion (x - x_1)(x - x_2)(x - x_3)
		#Lets set them equal to each other
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = (x - x_1)(x - x_2)(x - x_3)
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = x^3 -x^2((x_3) + (x_2) + (x_1)) + x((x_1)(x_2) + (x_1)(x_3) + (x_2)(x_3)) - (x_1)(x_2)(x_3)

		# That means that -x^2(m^2) = -x^2((x_3) + (x_2) + (x_1))
		# (m^2) = ((x_3) + (x_2) + (x_1))
		# x_3 = (m^2) - (x_2) - (x_1)

		# x = m^2 -x_1 -x_2
		result_x = (slope**2 - point1.x - point2.x) % self.prime_mod

		#Once we know x its easy to find y
		# y = mx + d
		# d = y_1 - m(x_1)
		# y = mx + y_1 - m(x_1)
		# y_3 = m(x_3) + y_1 - m(x_1)
		# y_3 = m((x_3) - (x_1)) + y_1

		#We take the negitive since we want -R which is reflected over the x axis
		result_y = (-(slope * (result_x - point1.x) + point1.y)) % self.prime_mod
		return Point(point_x=result_x, point_y=result_y, curve=self)

	def _double_point(self, point1):
		#Find the tangent of the line at the point
		#This is done by taking the dirivitive of the Cure formula y^2 = x^3 + a*x + b (mod p)
		# 2y = 3x^2 + a 
		slope = (3 * point1.x**2 + self.a) * modinv(2 * point1.y, self.prime_mod)

		#Compute the new X point
		# y = mx + d
		# d = y_1 - m(x_1)

		# y^2 = x^3 + a*x + b
		# b = (y_1)^2 - (x_1)^3 + x(x_1)

		# y^2 = (mx + d)^2 
		#     = m^2x^2 + 2mxd + d^2 
		#     = m^2x^2 + 2mx(y_1 - m(x_1)) + (y_1 - m(x_1))^2
		#     = x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2

		# Set the functions equal to each other and solve for zero
		# x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2 = x^3 + a*x + b
		# x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2 -x^3 - a*x - b = 0
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = 0


		#We know the roots of the equastion (x - x_1)(x - x_2)(x - x_3)
		#Lets set them equal to each other
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = (x - x_1)(x - x_1)(x - x_3)
		# x^3 - x^2(m^2) - 2x(m(y_1) + (m^2)(x_1)) - (y_1)^2 + 2m(x_1)(y_1) - m^2(x_1)^2 + a*x + b = + x^3 - x^2(2(x_1) + (x_3)) + x(x_1)^2 + 2x(x_1)(x_3)  -(x_1)^2(x_3)

		# That means that - x^2(m^2) = - x^2(2(x_1) + (x_3))
		# m^2 = 2(x_1) + (x_3)
		# m^2 - 2(x_1) = (x_3)

		# Compute the new point. This is the same info from the add point
		# Since there is no second point it is just 2* the same point
		result_x = (slope**2 - (2 * point1.x)) % self.prime_mod

		# y   = m*(x - x_1) + y_1
		# y_3 = m*(x_3 - x_1) + y_1

		#We take the negitive since we want -R which is reflected over the x axis
		result_y = (-(slope * (result_x - point1.x) + point1.y)) % self.prime_mod
		return Point(point_x=result_x, point_y=result_y, curve=self)

	def _neg_point(self, point):
		#Negation returns the other point on the curve
		return Point(point_x=point.x, point_y=(-point.y % self.prime_mod), curve=self)

	def find_points_by_x(self, x):
		# Rearrange the Curve Formula to get y. y = (x^3 + ax + b)^1/2
		y = modular_sqrt((pow(x, 3, self.prime_mod) + (x * self.a) + self.b) % self.prime_mod, self.prime_mod)
		return y


class MontgomeryCurve(Curve):
	"""
	by^2 = x^3 + ax^2 + x
	https://en.wikipedia.org/wiki/Montgomery_curve
	"""

	def _is_on_curve(self, point):
		#Use the Curve definition to check that x and y are valid. by^2 = x^3 + ax^2 + x
		y_side = self.b * (point.y ** 2)
		x_side = (point.x**3) + (self.a * (point.x **2)) + point.x

		# Make it easier by checking if x^3 + ax^2 + x - by^2 = 0 mod p
		return (y_side - x_side) % self.prime_mod == 0

	def _add_point(self, point1, point2):
		#Find the slope of the line that connects the two points
		# Compute the slope using y2-y1/x2-x1. Using a mod inverse instead of division
		slope = (point2.y - point1.y) * modinv(point2.x - point1.x, self.prime_mod)

		#Compute the new X point
		# y = mx + d
		# d = y_1 - m(x_1)
		# y = mx + y_1 - m(x_1)
		# y = m(x - (x_1)) + y_1

		# by^2 = x^3 + ax^2 + x

		# Set the functions equal to each other and solve for zero
		# b(mx + d)^2 = x^3 + ax^2 + x
		# b(d^2 + 2dmx + m^2 x^2) = x^3 + ax^2 + x
		# b(y_1)^2m^2 - 2b(y_1)m^2x - 2(x_1)b(y_1)m + bm^2x^2 + 2(x_1)bmx + b(x_1)^2 = x^3 + ax^2 + x
		# 0 = x^3 + ax^2 + x -b(y_1)^2m^2 + 2b(y_1)m^2x + 2(x_1)b(y_1)m - bm^2x^2 - 2(x_1)bmx - b(x_1)^2
		# x^3 + x^2(a - bm^2) + x(1 - 2(x_1)bm + 2b(y_1)m^2) - b(y_1)^2m^2  + 2(x_1)b(y_1)m - b(x_1)^2 = 0


		#We know the roots of the equastion (x - x_1)(x - x_2)(x - x_3)
		#Lets set them equal to each other
		# x^3 + x^2(a - bm^2) + x(1 - 2(x_1)bm + 2b(y_1)m^2) - b(y_1)^2m^2  + 2(x_1)b(y_1)m - b(x_1)^2 = (x - x_1)(x - x_2)(x - x_3)
		# x^3 + x^2(a - bm^2) + x(1 - 2(x_1)bm + 2b(y_1)m^2) - b(y_1)^2m^2  + 2(x_1)b(y_1)m - b(x_1)^2 = x^3 + x^2(-(x_3) - (x_2) - (x_1)) + x((x_1)(x_2) + (x_1)(x_3) + (x_2)(x_3)) - (x_1)(x_2)(x_3)

		# That means that x^2(a - bm^2) =  x^2(-(x_3) - (x_2) - (x_1))
		# a - bm^2 = -(x_3) - (x_2) - (x_1)
		# a - bm^2 + (x_2) + (x_1) = -(x_3)
		# (x_3) = bm^2 -a - (x_2) - (x_1)
		result_x = (self.b * (slope ** 2) - self.a - point2.x - point1.x) % self.prime_mod

		#Once we know x its easy to find y
		# y = mx + d
		# d = y_1 - m(x_1)
		# y = mx + y_1 - m(x_1)
		# y_3 = m(x_3) + y_1 - m(x_1)
		# y_3 = m((x_3) - (x_1)) + y_1

		#We take the negitive since we want -R which is reflected over the x axis
		result_y = (-(slope * (result_x - point1.x) + point1.y)) % self.prime_mod
		return Point(result_x, result_y, self)

	def _double_point(self, point1):
		#Find the tangent of the line at the point
		#This is done by taking the dirivitive of the Cure formula by^2 = x^3 + ax^2 + x (mod p)
		# 2by = 3x^2 + 2ax + 1 
		slope = (3 * point1.x**2 + 2 * self.a * point1.x + 1) * modinv(2 * self.b * point1.y, self.prime_mod)

		#Compute the new X point
		# y = mx + d
		# d = y_1 - m(x_1)

		# by^2 = x^3 + ax^2 + x

		# y^2 = (mx + d)^2 
		#     = m^2x^2 + 2mxd + d^2 
		#     = m^2x^2 + 2mx(y_1 - m(x_1)) + (y_1 - m(x_1))^2
		#     = x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2

		# Set the functions equal to each other and solve for zero
		# b(x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2) = x^3 + ax^2 + x
		# bx^2(m^2) + 2bx(m(y_1) - (m^2)(x_1)) + b(y_1)^2 - 2bm(x_1)(y_1) + bm^2(x_1)^2) - x^3 - ax^2 - x = 0
		# - x^3 + x^2(b(m^2) - a) + 2bx(m(y_1) - (m^2)(x_1)) + b(y_1)^2 - 2bm(x_1)(y_1) + bm^2(x_1)^2) - x = 0


		#We know the roots of the equastion (x - x_1)(x - x_2)(x - x_3)
		#Lets set them equal to each other
		# - x^3 + x^2(b(m^2) - a) + 2bx(m(y_1) - (m^2)(x_1)) + b(y_1)^2 - 2bm(x_1)(y_1) + bm^2(x_1)^2) - x = (x - x_1)(x - x_1)(x - x_3)
		# x^3 - x^2(b(m^2) - a) - 2bx(m(y_1) + (m^2)(x_1)) - b(y_1)^2 + 2bm(x_1)(y_1) - bm^2(x_1)^2) + x = x^3 - x^2(2(x_1) + (x_3)) + x(x_1)^2 + 2x(x_1)(x_3)  -(x_1)^2(x_3)

		# That means that - x^2(b(m^2) - a) = - x^2(2(x_1) + (x_3))
		# b(m^2) - a = 2(x_1) + (x_3)
		# b(m^2) - a - 2(x_1) = (x_3)
		result_x = (self.b * slope ** 2 - self.a - 2 * point1.x) % self.prime_mod

		#Once we know x its easy to find y
		# y = mx + d
		# d = y_1 - m(x_1)
		# y = mx + y_1 - m(x_1)
		# y_3 = m(x_3) + y_1 - m(x_1)
		# y_3 = m((x_3) - (x_1)) + y_1

		#We take the negitive since we want -R which is reflected over the x axis
		result_y = (-(slope * (result_x - point1.x) + point1.y) ) % self.prime_mod
		return Point(result_x, result_y, self)

	def _neg_point(self, point1):
		return Point(point1.x, -point1.y % self.prime_mod, self)

	def find_points_by_x(self, x):
		# Rearrange the Curve Formula to get y. y = ((x^3 + ax^2 + x)/b)^1/2
		y_squared = ((x **3 + self.a * x **2 + x) % self.prime_mod * modinv(self.b, self.prime_mod)) % self.prime_mod
		y = modular_sqrt(y_squared, self.prime_mod)
		return y


class TwistedEdwardsCurve(Curve):
	"""
	x^2 + y^2 = 1 + bx^2y^2
	https://en.wikipedia.org/wiki/Twisted_Edwards_curve
	"""
	def _is_on_curve(self, point1):
		#Use the Curve definition to check that x and y are valid. ax^2 + y^2 = 1 + bx^2y^2
		left_side_eq  = self.a * point1.x **2  + point1.y **2 
		right_side_eq = 1 + self.b * point1.x **2  + point1.y **2 

		# Make it easier by checking if x^3 + ax^2 + x - by^2 = 0 mod p
		return (left_side_eq - right_side_eq) % self.prime_mod == 0

	def _add_point(self, point1, point2):
		#Find the slope of the line that connects the two points
		# Compute the slope using y2-y1/x2-x1. Using a mod inverse instead of division
		slope = (point2.y - point1.y) * modinv(point2.x - point1.x, self.prime_mod)


		#Compute the new X point
		# y = mx + d
		# d = y_1 - m(x_1)

		# ax^2 + y^2 = 1 + bx^2y^2

		# y^2 = (mx + d)^2 
		#     = m^2x^2 + 2mxd + d^2 
		#     = m^2x^2 + 2mx(y_1 - m(x_1)) + (y_1 - m(x_1))^2
		#     = x^2(m^2) + 2x(m(y_1) - (m^2)(x_1)) + (y_1)^2 - 2m(x_1)(y_1) + m^2(x_1)^2

		# Set the functions equal to each other and solve for zero
		# ax^2 + y^2 = 1 + bx^2y^2
		# ax^2 + m^2x^2 + 2mxd + d^2 = 1 + bx^2(m^2x^2 + 2mxd + d^2)
		# 0 = x^4(bm^2) + x^3(2bmd) - x^2(a + m^2 - bd^2) - x(2md) - d^2 + 1

		#We know the roots of the equastion (x - x_1)(x - x_2)(x - x_3)
		#Lets set them equal to each other
		# x^4(bm^2) + x^3(2bmd) - x^2(a + m^2 - bd^2) - x(2md) - d^2 + 1 = (x - x_1)(x - x_2)(x - x_3)
		# x^4(bm^2) + x^3(2bmd) - x^2(a + m^2 - bd^2) - x(2md) - d^2 + 1 = x^3 + x^2(-(x_3) - (x_2) - (x_1)) + x((x_1)(x_2) + (x_1)(x_3) + (x_2)(x_3)) - (x_1)(x_2)(x_3)


		# That means that - x^2(a + m^2 - bd^2) = x^2(-(x_3) - (x_2) - (x_1))
		# a + m^2 - b((y_1) - m(x_1))^2 = (x_3) + (x_2) + (x_1)
		# a + m^2 - b(y_1)^2 - 2mb(y_1)(x_1) + b(x_1)^2 - (x_2) - (x_1) = (x_3) 


		# xR = (x_1 * y_2 + y_1 * x_1) / (1 + b * xP * xQ * yP * yQ)
		

		up_x = P.x * Q.y + P.y * Q.x
		down_x = 1 + self.b * P.x * Q.x * P.y * Q.y
		res_x = (up_x * modinv(down_x, self.prime_mod)) % self.prime_mod
		# yR = (yP * yQ - a * xP * xQ) / (1 - b * xP * xQ * yP * yQ)
		up_y = P.y * Q.y - self.a * P.x * Q.x
		down_y = 1 - self.b * P.x * Q.x * P.y * Q.y
		res_y = (up_y * modinv(down_y, self.prime_mod)) % self.prime_mod
		return Point(res_x, res_y, self)

	def _double_point(self, P: Point) -> Point:
		# xR = (2 * xP * yP) / (a * xP^2 + yP^2)
		up_x = 2 * P.x * P.y
		down_x = self.a * P.x * P.x + P.y * P.y
		res_x = (up_x * modinv(down_x, self.prime_mod)) % self.prime_mod
		# yR = (yP^2 - a * xP * xP) / (2 - a * xP^2 - yP^2)
		up_y = P.y * P.y - self.a * P.x * P.x
		down_y = 2 - self.a * P.x * P.x - P.y * P.y
		res_y = (up_y * modinv(down_y, self.prime_mod)) % self.prime_mod
		return Point(res_x, res_y, self)

	def _neg_point(self, P: Point) -> Point:
		return Point(-P.x % self.prime_mod, P.y, self)

	def find_points_by_x(self, x):
		# (bx^2 - 1) * y^2 = ax^2 - 1
		right = self.a * x * x - 1
		left_scale = (self.b * x * x - 1) % self.prime_mod
		inv_scale = modinv(left_scale, self.prime_mod)
		right = (right * inv_scale) % self.prime_mod
		y = modular_sqrt(right, self.prime_mod)
		return y


#Short Weierstrass Curves

#NOT SAFE
Anomalous = ShortWeierstrassCurve(
	name="Anomalous",
	a=15347898055371580590890576721314318823207531963035637503096292,
	b=7444386449934505970367865204569124728350661870959593404279615,
	prime_mod=0xb0000000000000000000000953000000000000000000001f9d7,
	order=0xb0000000000000000000000953000000000000000000001f9d7,
)
Anomalous_Generator_Point = Point(curve=Anomalous, point_x=0x101efb35fd1963c4871a2d17edaafa7e249807f58f8705126c6, point_y=0x22389a3954375834304ba1d509a97de6c07148ea7f5951b20e7)

#NOT SAFE
BN2254 = ShortWeierstrassCurve(
	name="BN(2,254)",
	a=0,
	b=2,
	prime_mod=0x2523648240000001ba344d80000000086121000000000013a700000000000013,
	order=0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d ,
)
BN2254_Generator_Point = Point(curve=BN2254, point_x=-1, point_y=1)

#NOT SAFE
brainpoolP256t1 = ShortWeierstrassCurve(
	name="brainpoolP256t1",
	a=-3,
	b=46214326585032579593829631435610129746736367449296220983687490401182983727876,
	prime_mod=0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
	order=0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7 ,
)
brainpoolP256t1_Generator_Point = Point(curve=brainpoolP256t1, point_x=0xa3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f4, point_y=0x2d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be)

#NOT SAFE
brainpoolP384t1 = ShortWeierstrassCurve(
	name="brainpoolP384t1",
	a=-3,
	b=19596161053329239268181228455226581162286252326261019516900162717091837027531392576647644262320816848087868142547438,
	prime_mod=0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
	order=0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565 ,
)
brainpoolP384t1_Generator_Point = Point(curve=brainpoolP384t1, point_x=0x18de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc, point_y=0x25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928)

#NOT SAFE
FRP256v1 = ShortWeierstrassCurve(
	name="FRP256v1",
	a=-3,
	b=107744541122042688792155207242782455150382764043089114141096634497567301547839,
	prime_mod=0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03,
	order=0xf1fd178c0b3ad58f10126de8ce42435b53dc67e140d2bf941ffdd459c6d655e1 ,
)
FRP256v1_Generator_Point = Point(curve=FRP256v1, point_x=0xb6b3d4c356c139eb31183d4749d423958c27d2dcaf98b70164c97a2dd98f5cff, point_y=0x6142e0f7c8b204911f9271f0f3ecef8c2701c307e8e4c9e183115a1554062cfb)

#NOT SAFE
P224 = ShortWeierstrassCurve(
	name="P224",
	a=-3,
	b=18958286285566608000408668544493926415504680968679321075787234672564,
	prime_mod=0xffffffffffffffffffffffffffffffff000000000000000000000001,
	order=0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d ,
)
P224_Generator_Point = Point(curve=P224, point_x=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, point_y=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)

#NOT SAFE
P256 = ShortWeierstrassCurve(
	name="P256",
	a=-3,
	b=41058363725152142129326129780047268409114441015993725554835256314039467401291,
	prime_mod=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
	order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 ,
)
P256_Generator_Point = Point(curve=P256, point_x=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, point_y=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

#NOT SAFE
secp256k1 = ShortWeierstrassCurve(
	name="secp256k1",
	a=0,
	b=7,
	prime_mod=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
	order=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
)
secp256k1_Generator_Point = Point(curve=secp256k1, point_x=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, point_y=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

#NOT SAFE
P384 = ShortWeierstrassCurve(
	name="P384",
	a=-3,
	b=27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575,
	prime_mod=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff ,
	order=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973 ,
)
P384_Generator_Point = Point(curve=P384, point_x=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, point_y=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)



#Montgomery Curves

Curve25519 = MontgomeryCurve(
	name="Curve25519",
	a=486662,
	b=1,
	prime_mod=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed,
	order=0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
)
Curve25519_Generator_Point = Point(curve=Curve25519, point_x=0x9, point_y=0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)

Curve383187 = MontgomeryCurve(
	name="Curve383187",
	a=229969,
	b=1,
	prime_mod=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45 ,
	order=0x1000000000000000000000000000000000000000000000000e85a85287a1488acd41ae84b2b7030446f72088b00a0e21 ,
)
Curve383187_Generator_Point = Point(curve=Curve383187, point_x=0x5, point_y=0x1eebe07dc1871896732b12d5504a32370471965c7a11f2c89865f855ab3cbd7c224e3620c31af3370788457dd5ce46df)


M221 = MontgomeryCurve(
	name="M221",
	a=117050,
	b=1,
	prime_mod=0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffd,
	order=0x40000000000000000000000000015a08ed730e8a2f77f005042605b,
)
M221_Generator_Point = Point(curve=M221, point_x=0x4, point_y=0xf7acdd2a4939571d1cef14eca37c228e61dbff10707dc6c08c5056d)


M383 = MontgomeryCurve(
	name="M383",
	a=2065150,
	b=1,
	prime_mod=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45,
	order=0x10000000000000000000000000000000000000000000000006c79673ac36ba6e7a32576f7b1b249e46bbc225be9071d7,
)
M383_Generator_Point = Point(curve=M383, point_x=0xc, point_y=0x1ec7ed04aaf834af310e304b2da0f328e7c165f0e8988abd3992861290f617aa1f1b2e7d0b6e332e969991b62555e77e)

M511 = MontgomeryCurve(
	name="M511",
	a=530438,
	b=1,
	prime_mod=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff45,
	order=0x100000000000000000000000000000000000000000000000000000000000000017b5feff30c7f5677ab2aeebd13779a2ac125042a6aa10bfa54c15bab76baf1b ,
)
M511_Generator_Point = Point(curve=M511, point_x=0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c, point_y=0xc)



#Twisted Curve

Curve1174 = TwistedEdwardsCurve(
	name="Curve1174",
	a=1,
	b=-1174,
	prime_mod=0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7 ,
	order=0x1fffffffffffffffffffffffffffffff77965c4dfd307348944d45fd166c971 ,
)
Curve1174_Generator_Point = Point(curve=Curve1174, point_x=0x37fbb0cea308c479343aee7c029a190c021d96a492ecd6516123f27bce29eda, point_y=0x6b72f82d47fb7cc6656841169840e0c4fe2dee2af3f976ba4ccb1bf9b46360e)

Curve41417 = TwistedEdwardsCurve(
	name="Curve41417",
	a=1,
	b=3617,
	prime_mod=0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffef ,
	order=0x7ffffffffffffffffffffffffffffffffffffffffffffffffffeb3cc92414cf706022b36f1c0338ad63cf181b0e71a5e106af79 ,
)
Curve41417_Generator_Point = Point(curve=Curve41417, point_x=0x1a334905141443300218c0631c326e5fcd46369f44c03ec7f57ff35498a4ab4d6d6ba111301a73faa8537c64c4fd3812f3cbc595, point_y=0x22)

E222 = TwistedEdwardsCurve(
	name="E222",
	a=1,
	b=160102,
	prime_mod=0x3fffffffffffffffffffffffffffffffffffffffffffffffffffff8b,
	order=0xffffffffffffffffffffffffffff70cbc95e932f802f31423598cbf,
)
E222_Generator_Point = Point(curve=E222, point_x=0x19b12bb156a389e55c9768c303316d07c23adab3736eb2bc3eb54e51, point_y=0x1c)


E382 = TwistedEdwardsCurve(
	name="E382",
	a=1,
	b=-67254,
	prime_mod=0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97,
	order=0xfffffffffffffffffffffffffffffffffffffffffffffffd5fb21f21e95eee17c5e69281b102d2773e27e13fd3c9719,
)
E382_Generator_Point = Point(curve=E382, point_x=0x196f8dd0eab20391e5f05be96e8d20ae68f840032b0b64352923bab85364841193517dbce8105398ebc0cc9470f79603, point_y=0x11)

E521 = TwistedEdwardsCurve(
	name="E521",
	a=1,
	b=-376014,
	prime_mod=0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
	order=0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b ,
)
E521_Generator_Point = Point(curve=E521, point_x=0x752cb45c48648b189df90cb2296b2878a3bfd9f42fc6c818ec8bf3c9c0c6203913f6ecc5ccc72434b1ae949d568fc99c6059d0fb13364838aa302a940a2f19ba6c, point_y=0xc)



Ed448 = TwistedEdwardsCurve(
	name="Ed448",
	a=1,
	b=-39081,
	prime_mod=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff ,
	order=0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3 ,
)
Ed448_Generator_Point = Point(curve=Ed448, point_x=0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f, point_y=0x13)




if __name__ == '__main__':
	#Test Identities
	#Check P + 0 = P
	test = secp256k1_Generator_Point + Point(curve=secp256k1, point_x=None, point_y=None)
	print(test == secp256k1_Generator_Point)

	#Check P + Q = Q + P
	test1 = secp256k1_Generator_Point + (5 * secp256k1_Generator_Point)
	test2 = (5 * secp256k1_Generator_Point) + secp256k1_Generator_Point
	print(test1 == test2)

	#Check P - P = 0
	test = secp256k1_Generator_Point - secp256k1_Generator_Point
	print(test)
	test = secp256k1_Generator_Point + secp256k1_Generator_Point.curve.neg_point(secp256k1_Generator_Point)
	print(test)

	#Check P + Q -R = 0
	r = secp256k1_Generator_Point + (5 * secp256k1_Generator_Point)
	neg_r = r.curve.neg_point(r)
	test = secp256k1_Generator_Point + (5 * secp256k1_Generator_Point) + neg_r
	print(test)

	print(secp256k1_Generator_Point+ secp256k1_Generator_Point+ secp256k1_Generator_Point)
	print(secp256k1_Generator_Point)

	#Show Generator multiplication 
	for k in range(0, 25):
		p = k * secp256k1_Generator_Point
		print(f"{k} * G = ({p.x}, {p.y})")

	"""
	for k in range(0, 25):
		p = k * Curve25519_Generator_Point
		print(f"{k} * G2 = ({p.x}, {p.y})")
	"""

	#Any point on the cure of a prime order is a genertor because the point is relitivly prime to the prime mod

	print("G on curve? {}".format(secp256k1_Generator_Point.curve.is_on_curve(secp256k1_Generator_Point)))

	print("R on curve? {}".format(E222_Generator_Point.curve.find_points_by_x(E222_Generator_Point.x)))

	#Check Add and mult
	print(secp256k1_Generator_Point == 1*secp256k1_Generator_Point)
	print(secp256k1_Generator_Point + secp256k1_Generator_Point == 2*secp256k1_Generator_Point)
	print(secp256k1_Generator_Point + secp256k1_Generator_Point + secp256k1_Generator_Point == 3*secp256k1_Generator_Point)

	#Check Point Compression and Decompression
	compressed_point = secp256k1_Generator_Point.compressed()
	decompressed_point = secp256k1_Generator_Point.decompress(compressed_point)
	assert secp256k1_Generator_Point == decompressed_point

	### Check for Invalid Curve Point Attacks 

	#### Values bigger than the Modulus
	G24 = Point(curve=secp256k1, point_x=115090238283566018960826468250608273126387416636633736439689841211757211870926 + 10*secp256k1.prime_mod, point_y=47185183227829754668635270747409548752084785367264057948864458978444304762303+ 10000*secp256k1.prime_mod)
	print(secp256k1.is_on_curve(G24))
	print(G24)

	#### Point is not on Curve
	invalid_point = Point(curve=secp256k1, point_x=secp256k1_Generator_Point.x, point_y=G24.y)
	print(secp256k1.is_on_curve(invalid_point))
	print(invalid_point)

	#### Point is not an Infinity Point





