import json
import xml.etree.ElementTree as et


# Factory Pattern
class Person:

    def __init__(self, first_name, last_name, age):
        self.first_name = first_name
        self.age = age
        self.last_name =last_name


class PersonDetails:

    # Factory Method
    # this is the application code that depends on an interface to complete its task.
    # here the application delegates the decision to the get_serializer method.
    def serialize(self, person, format):
        serializer = get_serializer(format)
        return serializer(person)


# The creator component. yeh btata hay k knsa concrete implementaion method run huga.
def get_serializer(format):
    if format == 'JSON':
        return _serialize_to_json
    elif format == 'XML':
        return _serialize_to_xml
    else:
        raise ValueError(format)


# method of concrete implementation
def _serialize_to_json(person):

    person_info = {
        'first_name': person.first_name,
        'last_name': person.last_name,
        'age': person.age,
    }
    return json.dumps(person_info)


# method of concrete implementation
def _serialize_to_xml(person):

    person_info = et.Element('person', attrib={'first_name': person.first_name})

    title = et.SubElement(person_info, 'last_name')
    title.text = person.last_name

    artist = et.SubElement(person_info, 'age')
    artist.text = person.age

    return et.tostring(person_info, encoding='unicode')


obj = Person('Maaz', 'Sabahuddin', '20')
print(PersonDetails().serialize(obj, 'JSON'))

