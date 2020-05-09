

class Singleton:
    __instance = None

    def __init__(self):
        Singleton.__instance = self

    @staticmethod
    def getInstance():
        if Singleton.__instance is None:
            Singleton()
        return Singleton.__instance


obj = Singleton()
print(obj)
obj = Singleton.getInstance()
print(obj)
