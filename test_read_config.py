from tcpdfilter import read_whitelist, UnreadableWhiteList
import pytest

def test_read_simple_config():
    simple_config = '''
- name: DNS replies
  src: 8.8.8.8
  dst: 192.168.1.12

- name: DNS queries
  src: 192.168.1.12
  dst: 8.8.8.8
  port: 53'''

    whitelist = read_whitelist(simple_config)

    assert whitelist[0].src == '8.8.8.8'
    assert whitelist[-1].port == 53


def test_it_raises_when_text_only_config():
    broken_config = '''this is a placeholder'''

    with pytest.raises(UnreadableWhiteList):
        whitelist = read_whitelist(broken_config)    


@pytest.mark.parametrize('content', (
    '''
    - name: something
      source: 1.1.1.1
    ''',
    '''
    - src: 1.1.1.1
    ''',
                                     ))
def test_it_raises_when_bad_format(content):
    with pytest.raises(UnreadableWhiteList):
        whitelist = read_whitelist(content)   