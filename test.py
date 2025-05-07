import ctypes
import gc


def count_references(address):
    """
    Count the number of references to the object at the given address.
    """
    return ctypes.c_long.from_address(address).value


def object_exists(obj_id):
    """
    Return True if the object with the given id exists.
    """
    for obj in gc.get_objects():
        if id(obj) == obj_id:
            return True
    return False


class Students:
    def __init__(self):
        self.boys = Boys(self)
        print(f"Students: {hex(id(self))}, Boys: {hex(id(self.boys))}")


class Boys:
    def __init__(self, students):
        self.students = students
        print(f"Boys: {hex(id(self))}, Students: {hex(id(self.students))}")


gc.disable()

students = Students()

students_id = id(students)
boys_id = id(students.boys)

print(f"Number of references to students: {count_references(students_id)}")  # 2

print(f"Number of references to boys: {count_references(boys_id)}")  # 1

print(f"Does students exist? {object_exists(students_id)}")  # True
print(f"Does boys exist? {object_exists(boys_id)}")  # True

students = None

print(f"Number of references to students: {count_references(students_id)}")  # 1

print(f"Number of references to boys: {count_references(boys_id)}")  # 1

print(f"Does students exist? {object_exists(students_id)}")  # True
print(f"Does boys exist? {object_exists(boys_id)}")  # True

print("Collecting garbage...")
# gc.collect()

print(f"Does students exist? {object_exists(students_id)}")  # False
print(f"Does boys exist? {object_exists(boys_id)}")  # False

print(f"Number of references to students: {count_references(students_id)}")  # 0

print(f"Number of references to boys: {count_references(boys_id)}")  # 0
