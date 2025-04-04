import collections

class ROListSlice(collections.abc.Sequence):

    def __init__(self, alist, start, alen):
        self.alist = alist
        self.start = start
        self.alen = alen

    def __len__(self):
        return self.alen

    def adj(self, i):
        if i<0: i += self.alen
        if i >= self.alen:
            raise IndexError()
        return i + self.start

    def __getitem__(self, i):
        return self.alist[self.adj(i)]
